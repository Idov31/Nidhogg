#include "pch.h"
#include "NofLoader.h"

_IRQL_requires_max_(APC_LEVEL)
NofLoader::NofLoader(_In_ IoctlCoff& coffData) {
	if (!coffData.Data ||
		coffData.DataSize == 0 ||
		!coffData.EntryName || 
		(coffData.ParameterSize == 0 && coffData.Parameter) ||
		(coffData.ParameterSize > 0 && !coffData.Parameter)) {
		ExRaiseStatus(STATUS_INVALID_PARAMETER);
	}
	entryNameSize = strnlen_s(coffData.EntryName, MAX_PATH);

	if (entryNameSize == 0 || entryNameSize >= MAX_PATH) {
		ExRaiseStatus(STATUS_INVALID_PARAMETER);
	}
	__try {
		ssdt = GetSSDTAddress();
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ExRaiseStatus(GetExceptionCode());
	}
	entryName = &coffData.EntryName[0];
	parameter = nullptr;
	parameterSize = coffData.ParameterSize;

	if (parameterSize > 0)
		parameter = coffData.Parameter;

	coff.Data = coffData.Data;
	coff.DataSize = coffData.DataSize;
	coff.Header = static_cast<PCOFF_FILE_HEADER>(coff.Data);

	if (coff.Header->PointerToSymbolTable >= coffData.DataSize) {
		ExRaiseStatus(STATUS_INVALID_PARAMETER);
	}

	coff.Symbol = reinterpret_cast<PCOFF_SYMBOL>(static_cast<PUCHAR>(coff.Data) + coff.Header->PointerToSymbolTable);
	coff.SecMap = AllocateMemory<PSECTION_MAP>(coff.Header->NumberOfSections * sizeof(SECTION_MAP), false);

	if (!coff.SecMap)
		ExRaiseStatus(STATUS_INVALID_PARAMETER);
	coff.FunMap = AllocateMemory<PCHAR>(COFF_FUNMAP_SIZE, false);

	if (!coff.FunMap) {
		FreeVirtualMemory(coff.SecMap);
		ExRaiseStatus(STATUS_INVALID_PARAMETER);
	}
}

_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NofLoader::~NofLoader() {
	FreeVirtualMemory(coff.FunMap);

	for (UINT16 i = 0; i < coff.Header->NumberOfSections; i++)
		FreeVirtualMemory(coff.SecMap[i].Ptr);
	FreeVirtualMemory(coff.SecMap);
}

/*
* Description:
* Load is responsible for loading the COFF file by processing its sections and applying the necessary relocations.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @status		[NTSTATUS] -- Whether the loading process succeeded or not.
*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NofLoader::Load() {
	NTSTATUS status = STATUS_SUCCESS;
	errno_t err = 0;
	UINT16 i = 0;

	for (i = 0; i < coff.Header->NumberOfSections; i++) {
		coff.Section = reinterpret_cast<PCOFF_SECTION>(static_cast<PUCHAR>(coff.Data) + 
			sizeof(COFF_FILE_HEADER) + 
			sizeof(COFF_SECTION) * i);

		// Handle BSS sections (uninitialized data)
		if (coff.Section->SizeOfRawData == 0) {
			if (coff.Section->VirtualSize > 0) {
				coff.SecMap[i].Ptr = AllocateMemory<PCHAR>(coff.Section->VirtualSize, false);
				
				if (!coff.SecMap[i].Ptr) {
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}
				coff.SecMap[i].Size = coff.Section->VirtualSize;
			}
			else {
				coff.SecMap[i].Ptr = nullptr;
				coff.SecMap[i].Size = 0;
			}
			continue;
		}

		if (!coff.Section->PointerToRawData) {
			coff.SecMap[i].Ptr = nullptr;
			coff.SecMap[i].Size = 0;
			continue;
		}
		bool isExecutable = (coff.Section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
		coff.SecMap[i].Ptr = AllocateMemory<PCHAR>(coff.Section->SizeOfRawData, false, false, isExecutable);

		if (!coff.SecMap[i].Ptr) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		coff.SecMap[i].Size = coff.Section->SizeOfRawData;
		err = memcpy_s(coff.SecMap[i].Ptr, 
			coff.Section->SizeOfRawData, 
			static_cast<PUCHAR>(coff.Data) + coff.Section->PointerToRawData, 
			coff.Section->SizeOfRawData);

		if (err != 0) {
			status = STATUS_INVALID_PARAMETER;
			FreeVirtualMemory(coff.SecMap[i].Ptr);
			break;
		}
	}

	if (!NT_SUCCESS(status)) {
		for (UINT16 j = 0; j < i; j++) {
			FreeVirtualMemory(coff.SecMap[j].Ptr);
		}
		return status;
	}
	status = ProcessSections();

	if (!NT_SUCCESS(status)) {
		for (UINT16 j = 0; j < coff.Header->NumberOfSections; j++) {
			FreeVirtualMemory(coff.SecMap[j].Ptr);
		}
	}
	return status;
}

/*
* Description:
* Execute is responsible for executing the loaded COFF file by calling its entry point with the provided data.
* 
* Parameters:
* There are no parameters.
* 
* Returns:
* @status		[NTSTATUS] -- Whether the execution process succeeded or not.
*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NofLoader::Execute() const {
	NTSTATUS status = STATUS_NOT_FOUND;
	tMainFunction Main = nullptr;

	for (UINT32 index = 0; index < coff.Header->NumberOfSymbols; index++) {
		if (coff.Symbol[index].First.Name[0]) {
			if (strncmp(coff.Symbol[index].First.Name, entryName, entryNameSize) == 0) {
				status = STATUS_SUCCESS;
				Main = reinterpret_cast<tMainFunction>(coff.SecMap[coff.Symbol[index].SectionNumber - 1].Ptr + 
					coff.Symbol[index].Value);
				Main(parameter, parameterSize);
				break;
			}
		}
	}

	return status;
}

/*
* Description:
* ProcessSymbol is responsible for getting a function address by its name. This function can be either from ntdll or ntoskrnl.
*
* Parameters:
* @symbolName      [_In_ LPSTR] -- Symbol's name (library$function format).
*
* Returns:
* @functionAddress [PCHAR]		-- Function address if found, else null.
*/
_IRQL_requires_(PASSIVE_LEVEL)
PCHAR NofLoader::ProcessSymbol(_In_ LPSTR symbolName) const noexcept {
	UNICODE_STRING uFunctionName = { 0 };
	PCHAR functionAddress = NULL;
	PCHAR trimmedSymbolName = strstr(symbolName, IMPORT_FUNCTION_PREFIX) + strlen(IMPORT_FUNCTION_PREFIX);
	PCHAR functionName = strstr(trimmedSymbolName, SYMBOL_DELIMITER) + 1;
	NTSTATUS status = ConvertAnsiToUnicode(functionName, &uFunctionName);

	if (!NT_SUCCESS(status)) {
		return nullptr;
	}

	if (strncmp(trimmedSymbolName, NTOSKRNL_SYMBOL, strlen(NTOSKRNL_SYMBOL)) == 0)
		functionAddress = static_cast<PCHAR>(MmGetSystemRoutineAddress(&uFunctionName));
	else if (strncmp(trimmedSymbolName, NTDLL_SYMBOL, strlen(NTDLL_SYMBOL)) == 0)
		functionAddress = static_cast<PCHAR>(GetSSDTFunctionAddress(ssdt, functionName));

	if (uFunctionName.Length != 0) {
		RtlFreeUnicodeString(&uFunctionName);
	}
	return functionAddress;
}

/*
* Description:
* ProcessSections is responsible for processing the COFF's sections and creating a valid section map.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @status [NTSTATUS] -- STATUS_SUCCESS if processed correctly, else error.
*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NofLoader::ProcessSections() {
	NTSTATUS status = STATUS_SUCCESS;
	UINT32 symbol = 0;
	PCHAR symbolName = NULL;
	PCHAR pFunction = NULL;
	SIZE_T bytesWritten = 0;
	UINT16 functionIndex = 0;
	UINT64 offsetLong = 0;
	UINT32 offset = 0;
	UINT32 relativeOffset = 0;
	errno_t err = 0;
	PCOFF_SYMBOL relocSymbol = nullptr;
	PCHAR targetAddress = nullptr;

	// Recalculate the symbol pointer to ensure it points to valid memory
	coff.Symbol = reinterpret_cast<PCOFF_SYMBOL>(static_cast<PUCHAR>(coff.Data) + coff.Header->PointerToSymbolTable);

	for (UINT16 sectionIndex = 0; sectionIndex < coff.Header->NumberOfSections; sectionIndex++) {
		coff.Section = reinterpret_cast<PCOFF_SECTION>(static_cast<PUCHAR>(coff.Data) + 
			sizeof(COFF_FILE_HEADER) + 
			(sizeof(COFF_SECTION) * sectionIndex));

		if (coff.Section->NumberOfRelocations == 0 || coff.Section->PointerToRelocations == 0)
			continue;

		if (coff.Section->PointerToRelocations >= coff.DataSize ||
			(coff.Section->PointerToRelocations + 
			(coff.Section->NumberOfRelocations * sizeof(COFF_RELOC))) > coff.DataSize) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		coff.Reloc = reinterpret_cast<PCOFF_RELOC>(static_cast<PUCHAR>(coff.Data) + 
			coff.Section->PointerToRelocations);

		for (UINT16 relocIndex = 0; relocIndex < coff.Section->NumberOfRelocations; relocIndex++) {
			if (coff.Reloc->SymbolTableIndex >= coff.Header->NumberOfSymbols) {
				status = STATUS_NO_DATA_DETECTED;
				break;
			}

			relocSymbol = &coff.Symbol[coff.Reloc->SymbolTableIndex];
			
			if (relocSymbol->First.Name[0] == 0) {
				symbol = relocSymbol->First.Value[1];
				symbolName = (reinterpret_cast<PCHAR>(coff.Symbol + coff.Header->NumberOfSymbols)) + symbol;
				pFunction = ProcessSymbol(symbolName);

				if (!pFunction) {
					status = STATUS_INVALID_PARAMETER;
					break;
				}

				if (coff.Reloc->Type == IMAGE_REL_AMD64_ADDR64) {
					err = memcpy_s(&offsetLong, 
						sizeof(UINT64), 
						coff.SecMap[sectionIndex].Ptr + coff.Reloc->VirtualAddress, 
						sizeof(UINT64));
					
					if (err != 0) {
						status = STATUS_ABANDONED;
						break;
					}
					offsetLong = reinterpret_cast<UINT64>(pFunction) + offsetLong;
					err = memcpy_s(coff.SecMap[sectionIndex].Ptr + coff.Reloc->VirtualAddress,
						sizeof(UINT64),
						&offsetLong,
						sizeof(UINT64));

					if (err != 0) {
						status = STATUS_ABANDONED;
						break;
					}
				}
				else if (coff.Reloc->Type == IMAGE_REL_AMD64_REL32) {
					relativeOffset = (coff.FunMap + (functionIndex * 8)) - (coff.SecMap[sectionIndex].Ptr + coff.Reloc->VirtualAddress + 4);

					if (relativeOffset > MAX_OFFSET) {
						status = STATUS_ABANDONED;
						break;
					}
					err = memcpy_s((coff.FunMap + (functionIndex * 8)),
						sizeof(UINT64),
						&pFunction,
						sizeof(UINT64));

					if (err != 0) {
						status = STATUS_ABANDONED;
						break;
					}

					offset = relativeOffset;
					err = memcpy_s(coff.SecMap[sectionIndex].Ptr + coff.Reloc->VirtualAddress,
						sizeof(UINT32), 
						&offset, 
						sizeof(UINT32));

					if (err != 0) {
						status = STATUS_ABANDONED;
						break;
					}
					functionIndex++;
				}
				else if (coff.Reloc->Type == IMAGE_REL_AMD64_ADDR32NB) {
					err = memcpy_s(&offset,
						sizeof(UINT32),
						coff.SecMap[sectionIndex].Ptr + coff.Reloc->VirtualAddress,
						sizeof(UINT32));

					if (err != 0) {
						status = STATUS_ABANDONED;
						break;
					}

					offset = static_cast<UINT32>(
						static_cast<PCHAR>(pFunction + offset) - 
						static_cast<PCHAR>(coff.SecMap[sectionIndex].Ptr + coff.Reloc->VirtualAddress + 4));

					if (offset > MAX_OFFSET) {
						status = STATUS_ABANDONED;
						break;
					}
					err = memcpy_s(coff.SecMap[sectionIndex].Ptr + coff.Reloc->VirtualAddress,
						sizeof(UINT32), 
						&offset, 
						sizeof(UINT32));
					if (err != 0) {
						status = STATUS_ABANDONED;
						break;
					}
				}
			}
			else {
				if (relocSymbol->SectionNumber > 0 && relocSymbol->SectionNumber <= coff.Header->NumberOfSections) {
					targetAddress = coff.SecMap[relocSymbol->SectionNumber - 1].Ptr + relocSymbol->Value;

					if (coff.Reloc->Type == IMAGE_REL_AMD64_ADDR64) {
						err = memcpy_s(&offsetLong, 
							sizeof(UINT64), 
							coff.SecMap[sectionIndex].Ptr + coff.Reloc->VirtualAddress, 
							sizeof(UINT64));

						if (err != 0) {
							status = STATUS_ABANDONED;
							break;
						}

						offsetLong = reinterpret_cast<UINT64>(targetAddress + offsetLong);
						err = memcpy_s(coff.SecMap[sectionIndex].Ptr + coff.Reloc->VirtualAddress,
							sizeof(UINT64), 
							&offsetLong,
							sizeof(UINT64));

						if (err != 0) {
							status = STATUS_ABANDONED;
							break;
						}
					}
					else if (coff.Reloc->Type == IMAGE_REL_AMD64_ADDR32NB) {
						err = memcpy_s(&offset,
							sizeof(UINT32), 
							coff.SecMap[sectionIndex].Ptr + coff.Reloc->VirtualAddress,
							sizeof(UINT32));
						
						if (err != 0) {
							status = STATUS_ABANDONED;
							break;
						}

						offset = static_cast<UINT32>(
							static_cast<PCHAR>(targetAddress + offset) - 
							static_cast<PCHAR>(coff.SecMap[sectionIndex].Ptr + coff.Reloc->VirtualAddress + 4));

						if (offset > MAX_OFFSET) {
							status = STATUS_ABANDONED;
							break;
						}
						
						err = memcpy_s(coff.SecMap[sectionIndex].Ptr + coff.Reloc->VirtualAddress,
							sizeof(UINT32),
							&offset, 
							sizeof(UINT32));

						if (err != 0) {
							status = STATUS_ABANDONED;
							break;
						}
					}
					else if (coff.Reloc->Type <= IMAGE_REL_AMD64_REL32_5 && coff.Reloc->Type >= IMAGE_REL_AMD64_REL32) {
						err = memcpy_s(&offset, 
							sizeof(UINT32), 
							coff.SecMap[sectionIndex].Ptr + coff.Reloc->VirtualAddress, 
							sizeof(UINT32));

						if (err != 0) {
							status = STATUS_ABANDONED;
							break;
						}
						
						relativeOffset = static_cast<UINT32>(
							targetAddress - 
							(coff.SecMap[sectionIndex].Ptr + coff.Reloc->VirtualAddress + 4));

						if (relativeOffset > MAX_OFFSET) {
							status = STATUS_ABANDONED;
							break;
						}

						offset += relativeOffset;
						offset += coff.Reloc->Type - IMAGE_REL_AMD64_REL32;

						err = memcpy_s(coff.SecMap[sectionIndex].Ptr + coff.Reloc->VirtualAddress,
							sizeof(UINT32), 
							&offset, 
							sizeof(UINT32));

						if (err != 0) {
							status = STATUS_ABANDONED;
							break;
						}
					}
				}
			}
			coff.Reloc = reinterpret_cast<PCOFF_RELOC>(reinterpret_cast<PUCHAR>(coff.Reloc) + sizeof(COFF_RELOC));
		}

		if (!NT_SUCCESS(status)) {
			if (status != STATUS_NO_DATA_DETECTED) {
				break;
			}
		}
	}
	return status;
}
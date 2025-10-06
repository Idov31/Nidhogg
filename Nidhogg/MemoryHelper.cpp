#include "pch.h"
#include "MemoryHelper.h"

/*
* Description:
* FindPatterns is responsible for finding one or more patterns in memory range.
*
* Parameters:
* @patterns		 [_In_ Pattern[]]	-- Pattern to search for.
* @patternsCount [_In_ SIZE_T]		-- Number of patterns to search for.
* @base			 [_In_ const PVOID] -- Base address for searching.
* @size			 [_In_ ULONG_PTR]	-- Address range to search in.
* @foundIndex	 [_Out_ PULONG]		-- Index of the found signature.
* @reversed		 [_In_ bool]		-- If want to reverse search or regular search.
*
* Returns:
* @address		 [PVOID]			-- Pattern's address if found, else 0.
*/
_IRQL_requires_max_(APC_LEVEL)
PVOID FindPatterns(_In_ const Pattern patterns[], _In_ SIZE_T patternsCount, _In_ const PVOID& base, _In_ ULONG_PTR size, _Out_opt_ PULONG foundIndex,
	_In_ KPROCESSOR_MODE mode) noexcept {
	PVOID address = nullptr;

	if (foundIndex)
		*foundIndex = 0;

	for (SIZE_T i = 0; i < patternsCount; i++) {
		address = FindPattern(patterns[i], base, size, foundIndex, mode);

		if (address) {
			if (!NT_SUCCESS(ProbeAddress(address, patterns[i].Length, sizeof(UCHAR)))) {
				address = nullptr;
				continue;
			}
			return address;
		}
	}
	return address;
}
/*
* Description:
* FindPattern is responsible for finding a pattern in memory range.
*
* Parameters:
* @pattern	  [_In_ Pattern]	 -- Pattern to search for.
* @base		  [_In_ const PVOID] -- Base address for searching.
* @size		  [_In_ ULONG_PTR]	 -- Address range to search in.
* @foundIndex [_Out_ PULONG]	 -- Index of the found signature.
* @reversed	  [_In_ bool]		 -- If want to reverse search or regular search.
*
* Returns:
* @address	  [PVOID]			 -- Pattern's address if found, else 0.
*/
_IRQL_requires_max_(APC_LEVEL)
PVOID FindPattern(_In_ Pattern pattern, _In_ const PVOID& base, _In_ ULONG_PTR size, _Out_opt_ PULONG foundIndex,
	_In_ KPROCESSOR_MODE mode) noexcept {
	bool found = false;

	if (foundIndex)
		*foundIndex = 0;

	if (!pattern.Data || !base || pattern.Length == 0 || size == 0 || pattern.Length > size)
		return nullptr;

	if (pattern.Versions.MinVersion > WindowsBuildNumber ||
		pattern.Versions.MaxVersion < WindowsBuildNumber)
		return nullptr;
	MemoryGuard guard(const_cast<PVOID>(base), static_cast<ULONG>(size), mode);

	if (!guard.IsValid())
		return nullptr;

	if (!pattern.Reversed) [[ likely ]] {
		for (ULONG_PTR i = 0; i < size; i++) {
			found = true;

			for (ULONG_PTR j = 0; j < pattern.Length; j++) {
				if (pattern.Data[j] != pattern.Wildcard && pattern.Data[j] != (static_cast<PCUCHAR>(base))[i + j]) {
					found = false;
					break;
				}
			}

			if (found) {
				if (foundIndex)
					*foundIndex = static_cast<ULONG>(i);
				return static_cast<PUCHAR>(base) + i + pattern.RelativeOffset;
			}
		}
	}
	else {
		for (int i = static_cast<int>(size); i >= 0; i--) {
			found = true;

			for (ULONG_PTR j = 0; j < pattern.Length; j++) {
				if (pattern.Data[j] != pattern.Wildcard && pattern.Data[j] != *(static_cast<PCUCHAR>(base) - i + j)) {
					found = false;
					break;
				}
			}

			if (found) {
				if (foundIndex)
					*foundIndex = i;
				return static_cast<PUCHAR>(base) - i - pattern.RelativeOffset;
			}
		}
	}

	return nullptr;
}

/*
* Description:
* CopyUnicodeString is responsible for copying unicode string.
*
* Parameters:
* @sourceProcess [_In_ const PEPROCESS&]   -- Source process.
* @source	     [_In_ PUNICODE_STRING]	   -- Source string.
* @targetProcess [_In_ const PEPROCESS&]   -- Target process.
* @target		 [_Inout_ PUNICODE_STRING] -- Target string.
* @mode			 [_In_ MODE]			   -- KernelMode / UserMode.
*
* Returns:
* @status		 [NTSTATUS]				   -- NTSUCCESS if succeeded else failure code.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS CopyUnicodeString(_In_ const PEPROCESS& sourceProcess, _In_ PUNICODE_STRING source, _In_ const PEPROCESS& targetProcess,
	_Inout_ PUNICODE_STRING target, _In_ MODE mode) {
	SIZE_T bytesWritten = 0;
	NTSTATUS status = STATUS_SUCCESS;

	target->Length = source->Length;
	target->MaximumLength = source->MaximumLength;

	if (!target->Buffer && mode == KernelMode) {
		target->Buffer = AllocateMemory<WCHAR*>(static_cast<SIZE_T>(target->Length));

		if (!target->Buffer)
			return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = MmCopyVirtualMemory(sourceProcess, source->Buffer, targetProcess,
		target->Buffer, target->Length, static_cast<KPROCESSOR_MODE>(mode), &bytesWritten);

	if (!NT_SUCCESS(status))
		FreeVirtualMemory(target->Buffer);
	return status;
}

/*
* Description:
* ProbeAddress is responsible for probing an address and returning specific status code on failure.
*
* Parameters:
* @address	   [PVOID]	  -- Address to probe.
* @len		   [SIZE_T]   -- Structure size.
* @alignment   [ULONG]    -- Address' required alignment.
*
* Returns:
* @status	   [NTSTATUS] -- NTSUCCESS if succeeded else failure code.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS ProbeAddress(_In_ const PVOID& address, _In_ SIZE_T len, _In_ ULONG alignment) {
	NTSTATUS status = STATUS_SUCCESS;

	if (!VALID_USERMODE_MEMORY(reinterpret_cast<ULONGLONG>(address)))
		return STATUS_INVALID_ADDRESS;

	__try {
		ProbeForRead(address, len, alignment);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}

	return status;
}

/*
* Description:
* WriteProcessMemory is responsible for writing data to any target process.
*
* Parameters:
* @sourceDataAddress [_In_ PVOID]			 -- The address of data to write.
* @targetProcess	 [_In_ const PEPROCESS&] -- Target process to write.
* @targetAddress	 [_In_ PVOID]			 -- Target address to write.
* @dataSize			 [_In_ SIZE_T]			 -- Size of data to write.
* @mode			     [_In_ MODE]			 -- Mode of the request (UserMode or KernelMode allowed).
* @alignAddr		 [_In_ bool]			 -- Whether to align the address or not.
*
* Returns:
* @status			 [NTSTATUS]				 -- Whether successfuly written or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS WriteProcessMemory(_In_ PVOID sourceDataAddress, _In_ const PEPROCESS& targetProcess, _Inout_ PVOID targetAddress,
	_In_ SIZE_T dataSize, _In_ MODE mode, _In_ bool alignAddr) {
	HANDLE hTargetProcess;
	ULONG oldProtection;
	SIZE_T patchLen;
	SIZE_T bytesWritten;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG alignment = static_cast<ULONG>(alignAddr ? dataSize : 1);

	if (mode != KernelMode && mode != UserMode)
		return STATUS_UNSUCCESSFUL;

	// Making sure that the given kernel mode address is valid.
	if (mode == KernelMode && (!VALID_KERNELMODE_MEMORY(reinterpret_cast<ULONG64>(sourceDataAddress)) ||
		(!VALID_KERNELMODE_MEMORY(reinterpret_cast<ULONG64>(targetAddress)) &&
			!NT_SUCCESS(ProbeAddress(targetAddress, dataSize, alignment))))) {
		status = STATUS_UNSUCCESSFUL;
		return status;
	}

	else if (mode == UserMode && (
		!NT_SUCCESS(ProbeAddress(sourceDataAddress, dataSize, static_cast<ULONG>(dataSize))) ||
		(!VALID_KERNELMODE_MEMORY((DWORD64)targetAddress) &&
			!NT_SUCCESS(ProbeAddress(targetAddress, dataSize, alignment))))) {
		status = STATUS_UNSUCCESSFUL;
		return status;
	}

	// Adding write permissions.
	status = ObOpenObjectByPointer(targetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, 
		static_cast<KPROCESSOR_MODE>(mode), &hTargetProcess);

	if (!NT_SUCCESS(status))
		return status;

	patchLen = dataSize;
	PVOID addressToProtect = targetAddress;
	status = ZwProtectVirtualMemory(hTargetProcess, &addressToProtect, &patchLen, PAGE_READWRITE, &oldProtection);

	if (!NT_SUCCESS(status)) {
		ZwClose(hTargetProcess);
		return status;
	}

	// Writing the data.
	status = MmCopyVirtualMemory(PsGetCurrentProcess(), sourceDataAddress, targetProcess, targetAddress, dataSize, KernelMode, &bytesWritten);

	// Restoring permissions and cleaning up.
	patchLen = dataSize;
	status = ZwProtectVirtualMemory(hTargetProcess, &addressToProtect, &patchLen, oldProtection, &oldProtection);
	ZwClose(hTargetProcess);
	return status;
}

/*
* Description:
* GetModuleBase is responsible for getting the base address of given module inside a given process.
*
* Parameters:
* @Process    [PEPROCESS] -- The process to search on.
* @moduleName [WCHAR*]	  -- Module's name to search.
*
* Returns:
* @moduleBase [PVOID]	  -- Base address of the module if found, else null.
*/
_IRQL_requires_max_(APC_LEVEL)
PVOID GetModuleBase(_In_ PEPROCESS process, _In_ const wchar_t* moduleName) {
	PVOID moduleBase = NULL;
	LARGE_INTEGER time = { 0 };
	time.QuadPart = ONE_SECOND;
	SIZE_T moduleLen = wcslen(moduleName);

	if (!process || moduleLen == 0)
		ExRaiseStatus(STATUS_INVALID_PARAMETER);

	PREALPEB targetPeb = reinterpret_cast<PREALPEB>(PsGetProcessPeb(process));

	if (!targetPeb)
		ExRaiseStatus(STATUS_ABANDONED);

	for (int i = 0; !targetPeb->LoaderData && i < 10; i++) {
		KeDelayExecutionThread(KernelMode, FALSE, &time);
	}

	if (!targetPeb->LoaderData)
		ExRaiseStatus(STATUS_ABANDONED);

	// Getting the module's image base.
	for (PLIST_ENTRY pListEntry = targetPeb->LoaderData->InLoadOrderModuleList.Flink;
		pListEntry != &targetPeb->LoaderData->InLoadOrderModuleList;
		pListEntry = pListEntry->Flink) {

		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (pEntry->FullDllName.Length == static_cast<USHORT>(moduleLen * 2)) {
			if (RtlCompareUnicodeStrings(pEntry->FullDllName.Buffer, moduleLen, moduleName, moduleLen, TRUE) == 0) {
				moduleBase = pEntry->DllBase;
				break;
			}
		}
	}

	if (!moduleBase)
		ExRaiseStatus(STATUS_NOT_FOUND);
	return moduleBase;
}

/*
* Description:
* GetUserModeFuncAddress is responsible for getting the function address inside given module from its EAT.
*
* Parameters:
* @functionName [_In_ const char*]	  -- Function name to search.
* @moduleName   [_In_ const wchar_t*] -- Module's name to search.
* @processName 	[_In_ wchar_t*]		  -- Process name to search.
*
* Returns:
* @PVOID							  -- Function address if found, else status is raised.
*/
_IRQL_requires_max_(APC_LEVEL)
PVOID GetUserModeFuncAddress(_In_ const char* functionName, _In_ const wchar_t* moduleName, _In_ const wchar_t* processName) {
	ULONG searchedPid = 0;

	__try {
		searchedPid = FindPidByName(processName);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ExRaiseStatus(GetExceptionCode());
	}

	return GetUserModeFuncAddress(functionName, moduleName, searchedPid);
}

/*
* Description:
* GetUserModeFuncAddress is responsible for getting the function address inside given module from its EAT.
*
* Parameters:
* @functionName [_In_ const char*]	  -- Function name to search.
* @moduleName   [_In_ const wchar_t*] -- Module's name to search.
* @pid 			[_In_ ULONG]		  -- Process id to search.
*
* Returns:
* @PVOID							  -- Function address if found, else status is raised.
*/
_IRQL_requires_max_(APC_LEVEL)
PVOID GetUserModeFuncAddress(_In_ const char* functionName, _In_ const wchar_t* moduleName, _In_ ULONG pid) {
	KAPC_STATE state;
	PVOID moduleBase = nullptr;
	PEPROCESS process = nullptr;
	PVOID functionAddress = nullptr;
	NTSTATUS status = PsLookupProcessByProcessId(ULongToHandle(pid), &process);

	if (!NT_SUCCESS(status))
		ExRaiseStatus(status);

	// Attaching to the process's stack to be able to walk the PEB.
	KeStackAttachProcess(process, &state);

	__try {
		moduleBase = GetModuleBase(process, moduleName);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(process);
		ExRaiseStatus(GetExceptionCode());
	}

	if (!moduleBase) {
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(process);
		ExRaiseStatus(STATUS_NOT_FOUND);
	}
	functionAddress = RtlFindExportedRoutineByName(moduleBase, functionName);

	KeUnstackDetachProcess(&state);
	ObDereferenceObject(process);

	if (!functionAddress)
		ExRaiseStatus(STATUS_NOT_FOUND);
	return functionAddress;
}

/*
* Description:
* GetSSDTFunctionAddress is responsible for getting the SSDT's location.
*
* Parameters:
* @ssdt			   [_In_ const PSYSTEM_SERVICE_DESCRIPTOR_TABLE] -- SSDT to search in.
* @functionName	   [_In_ const char*]							 -- Function name to search.
*
* Returns:
* @functionAddress [PVOID]										 -- Function address if found.
*/
_IRQL_requires_max_(APC_LEVEL)
PVOID GetSSDTFunctionAddress(_In_ const PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt, _In_ const char* functionName) {
	KAPC_STATE state;
	PEPROCESS csrssProcess = NULL;
	PVOID functionAddress = NULL;
	PVOID ntdllFunctionAddress = NULL;
	SIZE_T index = 0;
	UCHAR syscall = 0;
	ULONG csrssPid = 0;
	errno_t err = 0;
	WCHAR* fullPath = nullptr;
	WCHAR* mainDriveLetter = nullptr;
	const WCHAR ntdllPath[] = L"\\Windows\\System32\\ntdll.dll";
	MemoryAllocator<WCHAR*> fullPathAllocator(&fullPath, (DRIVE_LETTER_SIZE + wcslen(ntdllPath)) * sizeof(WCHAR));

	if (!fullPathAllocator.IsValid())
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	__try {
		csrssPid = FindPidByName(L"csrss.exe");
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ExRaiseStatus(GetExceptionCode());
	}
	NTSTATUS status = PsLookupProcessByProcessId(ULongToHandle(csrssPid), &csrssProcess);

	if (!NT_SUCCESS(status))
		ExRaiseStatus(status);

	// Attaching to the process's stack to be able to walk the PEB.
	IrqlGuard irqlGuard(PASSIVE_LEVEL);
	__try {
		mainDriveLetter = GetMainDriveLetter();
		err = wcscpy_s(fullPath, DRIVE_LETTER_SIZE * sizeof(WCHAR), mainDriveLetter);

		if (err != 0)
			ExRaiseStatus(STATUS_INVALID_PARAMETER);
		err = wcscat_s(fullPath, wcslen(ntdllPath) * sizeof(WCHAR), ntdllPath);

		if (err != 0)
			ExRaiseStatus(STATUS_INVALID_PARAMETER);
		ntdllFunctionAddress = GetUserModeFuncAddress(functionName, fullPath, csrssPid);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ObDereferenceObject(csrssProcess);
		FreeVirtualMemory(mainDriveLetter);
		ExRaiseStatus(GetExceptionCode());
	}
	FreeVirtualMemory(mainDriveLetter);
	irqlGuard.UnsetIrql();

	KeStackAttachProcess(csrssProcess, &state);

	// Searching for the syscall
	while ((static_cast<PUCHAR>(ntdllFunctionAddress))[index] != RETURN_OPCODE) {
		if ((static_cast<PUCHAR>(ntdllFunctionAddress))[index] == MOV_EAX_OPCODE) {
			syscall = (static_cast<PUCHAR>(ntdllFunctionAddress))[index + 1];
		}
		index++;
	}
	KeUnstackDetachProcess(&state);

	if (!syscall) {
		ObDereferenceObject(csrssProcess);
		ExRaiseStatus(STATUS_NOT_FOUND);
	}
	ObDereferenceObject(csrssProcess);

	__try {
		if (syscall != 0)
			functionAddress = ssdt->ServiceTableBase + (ssdt->ServiceTableBase[syscall] >> SYSCALL_SHIFT);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ExRaiseStatus(GetExceptionCode());
	}

	if (functionAddress == nullptr)
		ExRaiseStatus(STATUS_NOT_FOUND);

	return functionAddress;
}


/*
* Description:
* GetSSDTAddress is responsible for getting the SSDT's location.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @status [NTSTATUS] -- STATUS_SUCCESS if found, else error.
*/
_IRQL_requires_max_(APC_LEVEL)
PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTAddress() {
	ULONG infoSize = 0;
	PVOID ssdtRelativeLocation = NULL;
	PVOID ntoskrnlBase = NULL;
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt = NULL;
	PRTL_PROCESS_MODULES info = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	// Getting ntoskrnl base first.
	status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &infoSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		FreeVirtualMemory(info);
		info = AllocateMemory<PRTL_PROCESS_MODULES>(infoSize);

		if (!info) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		status = ZwQuerySystemInformation(SystemModuleInformation, info, infoSize, &infoSize);
	}

	if (!NT_SUCCESS(status) || !info)
		ExRaiseStatus(status);
	PRTL_PROCESS_MODULE_INFORMATION modules = info->Modules;

	for (ULONG i = 0; i < info->NumberOfModules; i++) {
		if (NtCreateFile >= modules[i].ImageBase &&
			static_cast<PVOID>(static_cast<PUCHAR>(modules[i].ImageBase) + modules[i].ImageSize) > NtCreateFile) {
			ntoskrnlBase = modules[i].ImageBase;
			break;
		}
	}

	if (!ntoskrnlBase) {
		FreeVirtualMemory(info);
		ExRaiseStatus(STATUS_NOT_FOUND);
	}
	PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(ntoskrnlBase);

	// Finding the SSDT address.
	status = STATUS_NOT_FOUND;

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		FreeVirtualMemory(info);
		ExRaiseStatus(STATUS_INVALID_ADDRESS);
	}

	PFULL_IMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PFULL_IMAGE_NT_HEADERS>(static_cast<PUCHAR>(ntoskrnlBase) + 
		dosHeader->e_lfanew);

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		FreeVirtualMemory(info);
		ExRaiseStatus(STATUS_INVALID_ADDRESS);
	}

	PIMAGE_SECTION_HEADER firstSection = reinterpret_cast<PIMAGE_SECTION_HEADER>(ntHeaders + 1);

	for (PIMAGE_SECTION_HEADER section = firstSection; section < firstSection + ntHeaders->FileHeader.NumberOfSections; section++) {
		if (strcmp(reinterpret_cast<const char*>(section->Name), ".text") == 0) {
			ssdtRelativeLocation = FindPattern(SsdtPattern, static_cast<PUCHAR>(ntoskrnlBase) + section->VirtualAddress, 
				section->Misc.VirtualSize, nullptr, KernelMode);

			if (ssdtRelativeLocation) {
				status = STATUS_SUCCESS;
				ssdt = reinterpret_cast<PSYSTEM_SERVICE_DESCRIPTOR_TABLE>(static_cast<PUCHAR>(ssdtRelativeLocation) + 
					*static_cast<PULONG>(ssdtRelativeLocation) + 4);
				break;
			}
		}
	}
	FreeVirtualMemory(info);

	if (!NT_SUCCESS(status))
		ExRaiseStatus(status);
	return ssdt;
}
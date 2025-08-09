#include "pch.h"
#include "MemoryHelper.hpp"

/*
* Description:
* FindPattern is responsible for finding a pattern in memory range.
*
* Parameters:
* @pattern		  [PCUCHAR]	    -- Pattern to search for.
* @wildcard		  [UCHAR]		-- Used wildcard.
* @len			  [ULONG_PTR]	-- Pattern length.
* @base			  [const PVOID] -- Base address for searching.
* @size			  [ULONG_PTR]	-- Address range to search in.
* @foundIndex	  [PULONG]	    -- Index of the found signature.
* @relativeOffset [ULONG]		-- If wanted, relative offset to get from.
* @reversed		  [bool]		-- If want to reverse search or regular search.
*
* Returns:
* @address		  [PVOID]	    -- Pattern's address if found, else 0.
*/
PVOID FindPattern(PCUCHAR pattern, UCHAR wildcard, ULONG_PTR len, const PVOID base, ULONG_PTR size,
	PULONG foundIndex, ULONG relativeOffset, bool reversed) {
	bool found = false;

	if (pattern == NULL || base == NULL || len == 0 || size == 0)
		return NULL;

	if (!reversed) {
		for (ULONG i = 0; i < size; i++) {
			found = true;

			for (ULONG j = 0; j < len; j++) {
				if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j]) {
					found = false;
					break;
				}
			}

			if (found) {
				if (foundIndex)
					*foundIndex = i;
				return (PUCHAR)base + i + relativeOffset;
			}
		}
	}
	else {
		for (int i = (int)size; i >= 0; i--) {
			found = true;

			for (ULONG j = 0; j < len; j++) {
				if (pattern[j] != wildcard && pattern[j] != *((PCUCHAR)base - i + j)) {
					found = false;
					break;
				}
			}

			if (found) {
				if (foundIndex)
					*foundIndex = i;
				return (PUCHAR)base - i - relativeOffset;
			}
		}
	}

	return NULL;
}

/*
* Description:
* FreeVirtualMemory is responsible for freeing virtual memory and null it.
*
* Parameters:
* @address [PVOID] -- Address to free.
*
* Returns:
* There is no return value.
*/
void FreeVirtualMemory(_In_ PVOID address) {
	if (!address)
		return;
	ExFreePoolWithTag(address, DRIVER_TAG);
	address = NULL;
}

/*
* Description:
* IsIContained is responsible for check if one unicode string contain another, case insensitive.
*
* Parameters:
* @container [UNICODE_STRING] -- Container string.
* @containee [const wchar_t*] -- Containee string.
*
* Returns:
* @contained [bool]			  -- True if contained else false.
*/
bool IsIContained(UNICODE_STRING container, const wchar_t* containee) {
	bool contained = false;
	SIZE_T containeeLen = wcslen(containee);

	if (container.Length < containeeLen || container.Length == 0 || containeeLen == 0)
		return contained;

	for (int i = 0; i <= container.Length - containeeLen; ++i) {
		if (_wcsnicmp(&container.Buffer[i], containee, containeeLen) == 0) {
			contained = true;
			break;
		}
	}
	return contained;
}

/*
* Description:
* CopyUnicodeString is responsible for copying unicode string.
*
* Parameters:
* @sourceProcess [PEPROCESS]	   -- Source process.
* @source	     [PUNICODE_STRING] -- Source string.
* @targetProcess [PEPROCESS]	   -- Target process.
* @target		 [PUNICODE_STRING] -- Target string.
* @mode			 [MODE]			   -- KernelMode / UserMode.
*
* Returns:
* @status		 [NTSTATUS] -- NTSUCCESS if succeeded else failure code.
*/
NTSTATUS CopyUnicodeString(PEPROCESS sourceProcess, PUNICODE_STRING source, PEPROCESS targetProcess, PUNICODE_STRING target, MODE mode) {
	SIZE_T bytesWritten = 0;
	NTSTATUS status = STATUS_SUCCESS;

	target->Length = source->Length;
	target->MaximumLength = source->MaximumLength;

	if (!target->Buffer) {
		target->Buffer = AllocateMemory<WCHAR*>(static_cast<SIZE_T>(target->Length));

		if (!target->Buffer)
			return STATUS_INSUFFICIENT_RESOURCES;
		memset(target->Buffer, 0, target->Length);
	}

	status = MmCopyVirtualMemory(sourceProcess, source->Buffer, targetProcess,
		target->Buffer, target->Length, (KPROCESSOR_MODE)mode, &bytesWritten);

	if (!NT_SUCCESS(status))
		ExFreePoolWithTag(target->Buffer, DRIVER_TAG);

	return status;
}

/*
* Description:
* FreeUnicodeString is responsible for freeing unicode string.
*
* Parameters:
* @source	     [PUNICODE_STRING] -- Source string.
*
* Returns:
* There is no return value.
*/
void FreeUnicodeString(PUNICODE_STRING source) {
	if (source->Buffer) {
		ExFreePoolWithTag(source->Buffer, DRIVER_TAG);
		source->Buffer = NULL;
		source->Length = 0;
		source->MaximumLength = 0;
	}
}

/*
* Description:
* ProbeAddress is responsible for probing an address and returning specific status code on failure.
*
* Parameters:
* @address	   [PVOID]	  -- Address to probe.
* @len		   [SIZE_T]   -- Structure size.
* @alignment   [ULONG]    -- Address' required alignment.
* @failureCode [NTSTATUS] -- Failure code.
*
* Returns:
* @status	   [NTSTATUS] -- NTSUCCESS if succeeded else failure code.
*/
NTSTATUS ProbeAddress(PVOID address, SIZE_T len, ULONG alignment, NTSTATUS failureCode) {
	NTSTATUS status = STATUS_SUCCESS;

	if (!VALID_USERMODE_MEMORY((ULONGLONG)address))
		return STATUS_ABANDONED;

	__try {
		ProbeForRead(address, len, alignment);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = failureCode;
	}

	return status;
}

/*
* Description:
* WriteProcessMemory is responsible for writing data to any target process.
*
* Parameters:
* @sourceDataAddress [PVOID]	 -- The address of data to write.
* @TargetProcess	 [PEPROCESS] -- Target process to write.
* @targetAddress	 [PVOID]	 -- Target address to write.
* @dataSize			 [SIZE_T]	 -- Size of data to write.
* @mode			     [MODE]		 -- Mode of the request (UserMode or KernelMode allowed).
* @alignAddr		 [bool]		 -- Whether to align the address or not.
*
* Returns:
* @status			 [NTSTATUS]	 -- Whether successfuly written or not.
*/
NTSTATUS WriteProcessMemory(PVOID sourceDataAddress, PEPROCESS TargetProcess, PVOID targetAddress,
	SIZE_T dataSize, MODE mode, bool alignAddr) {
	HANDLE hTargetProcess;
	ULONG oldProtection;
	SIZE_T patchLen;
	SIZE_T bytesWritten;
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_T alignment = alignAddr ? dataSize : 1;

	if (mode != KernelMode && mode != UserMode)
		return STATUS_UNSUCCESSFUL;

	// Making sure that the given kernel mode address is valid.
	if (mode == KernelMode && (!VALID_KERNELMODE_MEMORY((DWORD64)sourceDataAddress) ||
		(!VALID_KERNELMODE_MEMORY((DWORD64)targetAddress) &&
			!NT_SUCCESS(ProbeAddress(targetAddress, dataSize, alignment, STATUS_UNSUCCESSFUL))))) {
		status = STATUS_UNSUCCESSFUL;
		return status;
	}

	else if (mode == UserMode && (
		!NT_SUCCESS(ProbeAddress(sourceDataAddress, dataSize, dataSize, STATUS_UNSUCCESSFUL)) ||
		(!VALID_KERNELMODE_MEMORY((DWORD64)targetAddress) &&
			!NT_SUCCESS(ProbeAddress(targetAddress, dataSize, alignment, STATUS_UNSUCCESSFUL))))) {
		status = STATUS_UNSUCCESSFUL;
		return status;
	}

	// Adding write permissions.
	status = ObOpenObjectByPointer(TargetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, (KPROCESSOR_MODE)mode, &hTargetProcess);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	patchLen = dataSize;
	PVOID addressToProtect = targetAddress;
	status = ZwProtectVirtualMemory(hTargetProcess, &addressToProtect, &patchLen, PAGE_READWRITE, &oldProtection);

	if (!NT_SUCCESS(status)) {
		ZwClose(hTargetProcess);
		return status;
	}
	ZwClose(hTargetProcess);

	// Writing the data.
	status = MmCopyVirtualMemory(PsGetCurrentProcess(), sourceDataAddress, TargetProcess, targetAddress, dataSize, KernelMode, &bytesWritten);

	// Restoring permissions and cleaning up.
	if (ObOpenObjectByPointer(TargetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, (KPROCESSOR_MODE)mode, &hTargetProcess) == STATUS_SUCCESS) {
		patchLen = dataSize;
		ZwProtectVirtualMemory(hTargetProcess, &addressToProtect, &patchLen, oldProtection, &oldProtection);
		ZwClose(hTargetProcess);
	}

	return status;
}

/*
* Description:
* ReadProcessMemory is responsible for read data from any target process.
*
* Parameters:
* @Process		 [PEPROCESS] -- Process to read data from.
* @sourceAddress [PVOID]	 -- Address to read data from.
* @targetAddress [PVOID]     -- Address to read data to.
* @dataSize		 [SIZE_T]	 -- Size of data to read.
* @mode			 [MODE]		 -- Mode of the request (UserMode or KernelMode allowed).
*
* Returns:
* @status		 [NTSTATUS]	 -- Whether successfuly read or not.
*/
NTSTATUS ReadProcessMemory(PEPROCESS Process, PVOID sourceAddress, PVOID targetAddress, SIZE_T dataSize, MODE mode) {
	SIZE_T bytesRead;

	if (mode != KernelMode && mode != UserMode)
		return STATUS_UNSUCCESSFUL;

	// Making sure that the given kernel mode address is valid.
	if (mode == KernelMode && !VALID_KERNELMODE_MEMORY((DWORD64)targetAddress))
		return STATUS_UNSUCCESSFUL;
	else if (mode == UserMode && !VALID_USERMODE_MEMORY((DWORD64)targetAddress))
		return STATUS_UNSUCCESSFUL;

	return MmCopyVirtualMemory(Process, sourceAddress, PsGetCurrentProcess(), targetAddress, dataSize, KernelMode, &bytesRead);
}
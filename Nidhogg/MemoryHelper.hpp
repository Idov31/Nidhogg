#pragma once
#include "pch.h"
#include "WindowsTypes.hpp"
#include "NidhoggCommon.h"

/*
* Description:
* AllocateMemory is responsible for allocating memory with the right function depends on the windows version.
*
* Parameters:
* @size [SIZE_T] -- Size to allocate.
*
* Returns:
* @ptr  [PVOID]  -- Allocated pointer on success else NULL.
*/
inline PVOID AllocateMemory(SIZE_T size) {
	return WindowsBuildNumber >= WIN_2004 ? 
		ExAllocatePool2(POOL_FLAG_PAGED, size, DRIVER_TAG) :
		ExAllocatePoolWithTag(PagedPool, size, DRIVER_TAG);
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
inline NTSTATUS CopyUnicodeString(PEPROCESS sourceProcess, PUNICODE_STRING source, PEPROCESS targetProcess, PUNICODE_STRING target, MODE mode) {
	SIZE_T bytesWritten = 0;
	NTSTATUS status = STATUS_SUCCESS;

	target->Length = source->Length;
	target->MaximumLength = source->MaximumLength;

	if (!target->Buffer) {
		target->Buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, target->Length, DRIVER_TAG);

		if (!target->Buffer)
			return STATUS_INSUFFICIENT_RESOURCES;
		memset(target->Buffer, 0, target->Length);
	}

	status = MmCopyVirtualMemory(sourceProcess, source->Buffer, targetProcess,
		target->Buffer, target->Length, mode, &bytesWritten);

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
inline void FreeUnicodeString(PUNICODE_STRING source) {
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
* @size		   [ULONG]    -- Expected size to read.
* @failureCode [NTSTATUS] -- Failure code.
*
* Returns:
* @status	   [NTSTATUS] -- NTSUCCESS if succeeded else failure code.
*/
inline NTSTATUS ProbeAddress(PVOID address, SIZE_T len, ULONG size, NTSTATUS failureCode) {
	NTSTATUS status = STATUS_SUCCESS;

	if (!VALID_USERMODE_MEMORY((ULONGLONG)address))
		return STATUS_ABANDONED;

	__try {
		ProbeForRead(address, len, size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = failureCode;
	}

	return status;
}

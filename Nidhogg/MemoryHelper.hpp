#pragma once
#include "pch.h"

extern "C" {
	#include "WindowsTypes.hpp"
}
#include "NidhoggCommon.h"

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
inline PVOID FindPattern(PCUCHAR pattern, UCHAR wildcard, ULONG_PTR len, const PVOID base, ULONG_PTR size,
	PULONG foundIndex, ULONG relativeOffset, bool reversed = false) {
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
		for (int i = size; i >= 0; i--) {
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
* AllocateMemory is responsible for allocating memory with the right function depends on the windows version.
*
* Parameters:
* @size [SIZE_T] -- Size to allocate.
*
* Returns:
* @ptr  [PVOID]  -- Allocated pointer on success else NULL.
*/
inline PVOID AllocateMemory(SIZE_T size, bool paged = true) {
	if (AllocatePool2 && WindowsBuildNumber >= WIN_2004) {
		return paged ? ((tExAllocatePool2)AllocatePool2)(POOL_FLAG_PAGED, size, DRIVER_TAG) :
			((tExAllocatePool2)AllocatePool2)(POOL_FLAG_NON_PAGED_EXECUTE, size, DRIVER_TAG);
	}

#pragma warning( push )
#pragma warning( disable : 4996)
	return paged ? ExAllocatePoolWithTag(PagedPool, size, DRIVER_TAG) :
		ExAllocatePoolWithTag(NonPagedPool, size, DRIVER_TAG);
#pragma warning( pop )
}

/*
* Description:
* IsIContained is responsible for check if one unicode string contain another, case insensitive.
*
* Parameters:
* @container [UNICODE_STRING] -- Container string.
* @containee [WCHAR*]		  -- Containee string.
*
* Returns:
* @status	 [bool]			  -- True if contained else false.
*/
inline bool IsIContained(UNICODE_STRING container, WCHAR* containee) {
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
inline NTSTATUS CopyUnicodeString(PEPROCESS sourceProcess, PUNICODE_STRING source, PEPROCESS targetProcess, PUNICODE_STRING target, MODE mode) {
	SIZE_T bytesWritten = 0;
	NTSTATUS status = STATUS_SUCCESS;

	target->Length = source->Length;
	target->MaximumLength = source->MaximumLength;

	if (!target->Buffer) {
		target->Buffer = (WCHAR*)AllocateMemory(target->Length);

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

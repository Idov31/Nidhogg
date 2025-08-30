#pragma once
#include "pch.h"

extern "C" {
	#include "WindowsTypes.h"
}
#include "ProcessHelper.h"
#include "NidhoggCommon.h"

constexpr SIZE_T RETURN_OPCODE = 0xC3;
constexpr SIZE_T MOV_EAX_OPCODE = 0xB8;
constexpr UCHAR SYSCALL_SHIFT = 4;
constexpr LONGLONG ONE_SECOND = -100ll * 10 * 1000;

constexpr auto IsValidSize = [](_In_ size_t dataSize, _In_ size_t structSize) -> bool {
	return dataSize != 0 && dataSize % structSize == 0;
};


PVOID FindPattern(PCUCHAR pattern, UCHAR wildcard, ULONG_PTR len, const PVOID base, ULONG_PTR size,
	PULONG foundIndex, ULONG relativeOffset, bool reversed = false);
void FreeVirtualMemory(_In_ PVOID address);
bool IsIContained(UNICODE_STRING container, const wchar_t* containee);
NTSTATUS CopyUnicodeString(PEPROCESS sourceProcess, PUNICODE_STRING source, PEPROCESS targetProcess, PUNICODE_STRING target, MODE mode);
void FreeUnicodeString(PUNICODE_STRING source);
NTSTATUS ProbeAddress(PVOID address, SIZE_T len, ULONG alignment, NTSTATUS failureCode);
NTSTATUS WriteProcessMemory(PVOID sourceDataAddress, PEPROCESS TargetProcess, PVOID targetAddress, SIZE_T dataSize, MODE mode, bool alignAddr = true);
NTSTATUS ReadProcessMemory(PEPROCESS Process, PVOID sourceAddress, PVOID targetAddress, SIZE_T dataSize, MODE mode);

_IRQL_requires_max_(APC_LEVEL)
PVOID GetModuleBase(_In_ PEPROCESS process, _In_ const wchar_t* moduleName);

_IRQL_requires_max_(APC_LEVEL)
PVOID GetUserModeFuncAddress(_In_ const char* functionName, _In_ const wchar_t* moduleName, _In_ ULONG pid);

_IRQL_requires_max_(APC_LEVEL)
PVOID GetUserModeFuncAddress(_In_ const char* functionName, _In_ const wchar_t* moduleName, _In_ const wchar_t* processName = L"csrss.exe");

_IRQL_requires_max_(APC_LEVEL)
PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTAddress();

_IRQL_requires_max_(APC_LEVEL)
PVOID GetSSDTFunctionAddress(_In_ const PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt, _In_ const char* functionName);

/*
* Description:
* AllocateVirtualMemory is responsible for allocating virtual memory with the right function depends on the windows version.
*
* Parameters:
* @size				    [size_t]	  -- Size to allocate.
* @paged				[bool]		  -- Paged or non-paged.
* @forceDeprecatedAlloc [bool]		  -- Force allocation with ExAllocatePoolWithTag.
*
* Returns:
* @ptr					[PointerType] -- Allocated pointer on success else NULL.
*/
template <typename PointerType>
inline PointerType AllocateMemory(size_t size, bool paged = true, bool forceDeprecatedAlloc = false) noexcept {
	PVOID allocatedMem = NULL;

	if (AllocatePool2 && WindowsBuildNumber >= WIN_2004 && !forceDeprecatedAlloc) {
		allocatedMem = paged ? ((tExAllocatePool2)AllocatePool2)(POOL_FLAG_PAGED, size, DRIVER_TAG) :
			((tExAllocatePool2)AllocatePool2)(POOL_FLAG_NON_PAGED, size, DRIVER_TAG);
	}
	else {
#pragma warning(push)
#pragma warning(disable : 4996)
		allocatedMem = paged ? ExAllocatePoolWithTag(PagedPool, size, DRIVER_TAG) :
			ExAllocatePoolWithTag(NonPagedPool, size, DRIVER_TAG);
#pragma warning(pop)
	}

	if (allocatedMem)
		RtlSecureZeroMemory(allocatedMem, size);
	return reinterpret_cast<PointerType>(allocatedMem);
}

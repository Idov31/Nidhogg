#pragma once
#include "pch.h"

extern "C" {
	#include "WindowsTypes.h"
}
#include "ProcessHelper.h"
#include "MemoryAllocator.hpp"
#include "NidhoggCommon.h"

constexpr SIZE_T RETURN_OPCODE = 0xC3;
constexpr SIZE_T MOV_EAX_OPCODE = 0xB8;
constexpr UCHAR SYSCALL_SHIFT = 4;
constexpr LONGLONG ONE_SECOND = -100ll * 10 * 1000;

constexpr auto IsValidSize = [](_In_ size_t dataSize, _In_ size_t structSize) -> bool {
	return dataSize != 0 && dataSize % structSize == 0;
};

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS ProbeAddress(_In_ const PVOID& address, _In_ SIZE_T len, _In_ ULONG alignment);

_IRQL_requires_max_(APC_LEVEL)
PVOID FindPattern(_In_ PCUCHAR pattern, _In_ UCHAR wildcard, _In_ ULONG_PTR len, _In_ const PVOID& base, _In_ ULONG_PTR size,
	_In_ ULONG relativeOffset, _Out_opt_ PULONG foundIndex, _In_ bool reversed = false) noexcept;

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS CopyUnicodeString(_In_ const PEPROCESS& sourceProcess, _In_ PUNICODE_STRING source, _In_ const PEPROCESS& targetProcess, 
	_Inout_ PUNICODE_STRING target, _In_ MODE mode);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS WriteProcessMemory(_In_ PVOID sourceDataAddress, _In_ const PEPROCESS& targetProcess, _Inout_ PVOID targetAddress, 
	_In_ SIZE_T dataSize, _In_ MODE mode, _In_ bool alignAddr = true);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS ReadProcessMemory(_In_ const PEPROCESS& process, _In_ PVOID sourceAddress, _Inout_ PVOID targetAddress, _In_ SIZE_T dataSize, 
	_In_ MODE mode);

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

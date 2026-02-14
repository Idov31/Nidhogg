#pragma once
#include "pch.h"

extern "C" {
	#include "WindowsTypes.h"
}
#include "IrqlGuard.h"
#include "ProcessHelper.h"
#include "FileHelper.h"
#include "MemoryAllocator.hpp"
#include "NidhoggCommon.h"

struct VersionRange {
	ULONG MinVersion;
	ULONG MaxVersion;
};

struct PatternOffset {
	ULONG MinVersion;
	ULONG MaxVersion;
	LONG Offset;
};

struct Pattern {
	VersionRange Versions;
	ULONG_PTR Length;
	PCUCHAR Data;
	UCHAR Wildcard;
	LONG RelativeOffset;
	bool Reversed;
	ULONG OffsetsCount;
	PatternOffset Offsets[SUPPORTED_VERSIONS_COUNT];

	LONG GetOffsetForVersion(ULONG version) const {
		for (ULONG i = 0; i < OffsetsCount; i++) {
			if (version >= Offsets[i].MinVersion && version <= Offsets[i].MaxVersion) {
				return Offsets[i].Offset;
			}
		}
		return 0;
	}
};

constexpr SIZE_T RETURN_OPCODE = 0xC3;
constexpr SIZE_T MOV_EAX_OPCODE = 0xB8;
constexpr UCHAR SYSCALL_SHIFT = 4;
constexpr LONGLONG ONE_SECOND = -100ll * 10 * 1000;
constexpr UCHAR SsdtSignature[] = { 0x4C, 0x8D, 0x15, 0xCC, 0xCC, 0xCC, 0xCC, 0x4C, 0x8D, 0x1D, 0xCC, 0xCC, 0xCC, 0xCC, 0xF7 };

constexpr Pattern SsdtPattern = {
	{WIN_1507, WIN_11_24H2},
	sizeof(SsdtSignature),
	SsdtSignature,
	0xCC,
	3,
	false
};

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS ProbeAddress(_In_ const PVOID& address, _In_ SIZE_T len, _In_ ULONG alignment);

_IRQL_requires_max_(APC_LEVEL)
PVOID FindPattern(_In_ Pattern pattern, 
	_In_ const PVOID base, 
	_In_ SIZE_T size, 
	_Out_opt_ PULONG foundIndex, 
	_In_ KPROCESSOR_MODE mode = KernelMode) noexcept;

_IRQL_requires_max_(APC_LEVEL)
PVOID FindPatterns(_In_ const Pattern patterns[], 
	_In_ SIZE_T patternsCount, 
	_In_ const PVOID base, 
	_In_ SIZE_T size, 
	_Out_opt_ PULONG foundIndex,
	_In_ KPROCESSOR_MODE mode = KernelMode) noexcept;

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS CopyUnicodeString(_In_ const PEPROCESS& sourceProcess, _In_ PUNICODE_STRING source, _In_ const PEPROCESS& targetProcess, 
	_Inout_ PUNICODE_STRING target, _In_ MODE mode);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS WriteProcessMemory(_In_ PVOID sourceDataAddress, _In_ const PEPROCESS& targetProcess, _Inout_ PVOID targetAddress, 
	_In_ SIZE_T dataSize, _In_ MODE mode, _In_ bool alignAddr = true);

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

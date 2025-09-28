#include "pch.h"
#include "ProcessHelper.h"

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
_IRQL_requires_max_(APC_LEVEL)
ULONG FindPidByName(_In_ const wchar_t* processName) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG pid = 0;
	PSYSTEM_PROCESS_INFO originalInfo = NULL;
	PSYSTEM_PROCESS_INFO info = NULL;
	ULONG infoSize = 0;

	if (!processName || wcslen(processName) == 0)
		ExRaiseStatus(STATUS_INVALID_PARAMETER);

	status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &infoSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		FreeVirtualMemory(originalInfo);
		originalInfo = AllocateMemory<PSYSTEM_PROCESS_INFO>(infoSize);

		if (!originalInfo)
			break;
		status = ZwQuerySystemInformation(SystemProcessInformation, originalInfo, infoSize, &infoSize);
	}

	if (!NT_SUCCESS(status) || !originalInfo) {
		if (!originalInfo)
			status = STATUS_INSUFFICIENT_RESOURCES;
		FreeVirtualMemory(originalInfo);
		ExRaiseStatus(status);
	}

	// Using another info variable to avoid BSOD on freeing.
	info = originalInfo;

	// Iterating the processes information until our pid is found.
	while (info->NextEntryOffset) {
		if (info->ImageName.Buffer && info->ImageName.Length > 0) {
			if (_wcsicmp(info->ImageName.Buffer, processName) == 0) {
				pid = HandleToULong(info->UniqueProcessId);
				break;
			}
		}
		info = reinterpret_cast<PSYSTEM_PROCESS_INFO>(reinterpret_cast<PUCHAR>(info) + info->NextEntryOffset);
	}

	FreeVirtualMemory(originalInfo);
	return status;
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
_IRQL_requires_max_(APC_LEVEL)
ULONG GetProcessLockOffset() {
	ULONG processLockOffset = 0;

	if (WindowsBuildNumber > LATEST_VERSION)
		return processLockOffset;

	switch (WindowsBuildNumber) {
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
	case WIN_11_24H2:
		processLockOffset = 0x1c8;
		break;
	default:
		processLockOffset = 0x438;
		break;
	}

	return processLockOffset;
}
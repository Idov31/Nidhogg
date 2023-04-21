#pragma once
#include "pch.h"

NTSTATUS ListObCallbacks(CallbacksList* Callbacks);
NTSTATUS MatchCallback(PVOID callack, CHAR driverName[MAX_DRIVER_PATH]);

/*
* Description:
* ListObCallbacks is responsible to list all registered ObCallbacks of certain type.
*
* Parameters:
* @Callbacks [ObCallbacksList*] -- All callbacks as list.
*
* Returns:
* @status	 [NTSTATUS]			-- Whether successfuly listed or not.
*/
NTSTATUS ListObCallbacks(CallbacksList* Callbacks) {
	NTSTATUS status = STATUS_SUCCESS;
	PFULL_OBJECT_TYPE objectType = NULL;
	CHAR driverName[MAX_DRIVER_PATH] = {0};
	ULONG index = 0;

	switch (Callbacks->Type) {
	case ObProcessType:
		objectType = (PFULL_OBJECT_TYPE)*PsProcessType;
		break;
	case ObThreadType:
		objectType = (PFULL_OBJECT_TYPE)*PsThreadType;
		break;
	default:
		status = STATUS_INVALID_PARAMETER;
		break;
	}

	if (!NT_SUCCESS(status))
		return status;

	ExAcquirePushLockExclusive((PULONG_PTR)&objectType->TypeLock);
	POB_CALLBACK_ENTRY currentObjectCallback = (POB_CALLBACK_ENTRY)(&objectType->CallbackList);

	if (Callbacks->NumberOfCallbacks == 0) {
		do {
			if (currentObjectCallback->Enabled) {
				if (currentObjectCallback->PostOperation || currentObjectCallback->PreOperation)
					Callbacks->NumberOfCallbacks++;
			}
			currentObjectCallback = (POB_CALLBACK_ENTRY)currentObjectCallback->CallbackList.Flink;
		} while ((PVOID)currentObjectCallback != (PVOID)(&objectType->CallbackList));
	}
	else {
		do {
			if (currentObjectCallback->Enabled) {
				if (currentObjectCallback->PostOperation) {
					if (NT_SUCCESS(MatchCallback(currentObjectCallback->PostOperation, driverName)))
						strcpy_s(Callbacks->Callbacks[index].DriverName, driverName);

					Callbacks->Callbacks[index].PostOperation = currentObjectCallback->PostOperation;
				}
				if (currentObjectCallback->PreOperation) {
					if (NT_SUCCESS(MatchCallback(currentObjectCallback->PreOperation, driverName)))
						if (strlen(Callbacks->Callbacks[index].DriverName) == 0)
							strcpy_s(Callbacks->Callbacks[index].DriverName, driverName);

					Callbacks->Callbacks[index].PreOperation = currentObjectCallback->PreOperation;
				}	
				index++;
			}
			currentObjectCallback = (POB_CALLBACK_ENTRY)currentObjectCallback->CallbackList.Flink;
		} while (index != Callbacks->NumberOfCallbacks && (PVOID)currentObjectCallback != (PVOID)(&objectType->CallbackList));
	}
	ExReleasePushLockExclusive((PULONG_PTR)&objectType->TypeLock);
	return status;
}

/*
* Description:
* MatchCallback is responsible to match the callback to its driver.
*
* Parameters:
* @callack	  [PVOID]    -- Callback's address.
* @driverName [PCHAR*]    -- Pointer to the driver name if found, else null.
*
* Returns:
* @status	  [NTSTATUS] -- Whether successfuly matched or not.
*/
NTSTATUS MatchCallback(PVOID callack, CHAR driverName[MAX_DRIVER_PATH]) {
	NTSTATUS status = STATUS_SUCCESS;
	PRTL_PROCESS_MODULES info = NULL;
	ULONG infoSize;

	status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &infoSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (info) {
			ExFreePoolWithTag(info, DRIVER_TAG);
			info = NULL;
		}

		info = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(PagedPool, infoSize, DRIVER_TAG);

		if (!info)
			return STATUS_INSUFFICIENT_RESOURCES;

		status = ZwQuerySystemInformation(SystemModuleInformation, info, infoSize, &infoSize);
	}

	if (!NT_SUCCESS(status) || !info)
		goto CleanUp;

	PRTL_PROCESS_MODULE_INFORMATION modules = info->Modules;

	for (ULONG i = 0; i < info->NumberOfModules; i++) {
		if (callack >= modules[i].ImageBase && callack < (PVOID)((PUCHAR)modules[i].ImageBase + modules[i].ImageSize)) {
			if (modules[i].FullPathName)
				strcpy_s(driverName, MAX_DRIVER_PATH, (const char*)modules[i].FullPathName);
			else
				status = STATUS_UNSUCCESSFUL;
			break;
		}
	}

CleanUp:
	if (info)
		ExFreePoolWithTag(info, DRIVER_TAG);
	return status;
}

#pragma once
#include "pch.h"

constexpr UCHAR PspCreateProcessNotifyRoutineSignature[] = { 0x4C, 0x8D, 0xCC };
constexpr UCHAR PspSetCreateProcessNotifyRoutineSignature[] = { 0xE8, 0xCC };
constexpr UCHAR PspCreateProcessNotifyRoutineCountExSignature[] = { 0xF0, 0xFF, 0x05, 0xCC };
constexpr SIZE_T PspSetCreateProcessNotifyRoutineSignatureDistance = 0x20;
constexpr SIZE_T PspCreateProcessNotifyRoutineDistance = 0xC3;
constexpr SIZE_T PsNotifyRoutinesRoutineOffset = 5;
constexpr SIZE_T RoutinesListOffset = 7;
constexpr SIZE_T PsNotifyRoutinesRoutineCountOffsetEx = 0x7;
constexpr SIZE_T PsNotifyRoutinesRoutineCountOffset = 0xB;

NTSTATUS RestoreCallback(KernelCallback* Callback);
NTSTATUS RemoveCallback(KernelCallback* Callback);
NTSTATUS ListObCallbacks(ObCallbacksList* Callbacks);
NTSTATUS ListPsNotifyRoutines(PsRoutinesList* Callbacks, ULONG64 ReplacerFunction, ULONG64 ReplacedFunction);
NTSTATUS MatchCallback(PVOID callack, CHAR driverName[MAX_DRIVER_PATH]);
OB_PREOP_CALLBACK_STATUS ObPreOpenDummyFunction(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);
VOID ObPostOpenDummyFunction(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION Info);
void CreateProcessNotifyExDummyFunction(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
void CreateProcessNotifyDummyFunction(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create);
NTSTATUS AddDisabledCallback(DisabledKernelCallback Callback);
NTSTATUS RemoveDisabledCallback(KernelCallback* Callback, DisabledKernelCallback* DisabledCallback);

/*
* Description:
* RestoreObCallback is responsible to restoring a certain callback from the callback list.
*
* Parameters:
* @Callback [KernelCallback*] -- Callback to remove.
*
* Returns:
* @status	[NTSTATUS]		  -- Whether successfuly removed or not.
*/
NTSTATUS RestoreCallback(KernelCallback* Callback) {
	DisabledKernelCallback callback{};
	NTSTATUS status = STATUS_NOT_FOUND;

	AutoLock locker(aaGlobals.Lock);
	status = RemoveDisabledCallback(Callback, &callback);

	if (!NT_SUCCESS(status))
		return status;

	if (Callback->Type == ObProcessType || Callback->Type == ObThreadType) {
		PFULL_OBJECT_TYPE objectType = NULL;

		switch (Callback->Type) {
		case ObProcessType:
			objectType = (PFULL_OBJECT_TYPE)*PsProcessType;
			break;
		case ObThreadType:
			objectType = (PFULL_OBJECT_TYPE)*PsThreadType;
			break;
		}

		ExAcquirePushLockExclusive((PULONG_PTR)&objectType->TypeLock);
		POB_CALLBACK_ENTRY currentObjectCallback = (POB_CALLBACK_ENTRY)(&objectType->CallbackList);

		do {
			if (currentObjectCallback->Enabled && (ULONG64)currentObjectCallback->Entry == callback.Entry) {
				if (currentObjectCallback->PreOperation == ObPreOpenDummyFunction) {
					currentObjectCallback->PreOperation = (POB_PRE_OPERATION_CALLBACK)callback.CallbackAddress;
					status = STATUS_SUCCESS;
					break;
				}
				else if (currentObjectCallback->PostOperation == ObPostOpenDummyFunction) {
					currentObjectCallback->PostOperation = (POB_POST_OPERATION_CALLBACK)callback.CallbackAddress;
					status = STATUS_SUCCESS;
					break;
				}
			}
			currentObjectCallback = (POB_CALLBACK_ENTRY)currentObjectCallback->CallbackList.Flink;
		} while ((PVOID)currentObjectCallback != (PVOID)(&objectType->CallbackList));

		ExReleasePushLockExclusive((PULONG_PTR)&objectType->TypeLock);
	}
	else if (Callback->Type == PsCreateProcessType || Callback->Type == PsCreateProcessTypeEx) {
		PsRoutinesList routines{};
		ULONG64 replacedFunction = 0;
		routines.Type = Callback->Type;

		switch (Callback->Type) {
		case PsCreateProcessType:
			replacedFunction = (ULONG64)CreateProcessNotifyDummyFunction;
		case PsCreateProcessTypeEx:
			replacedFunction = (ULONG64)CreateProcessNotifyExDummyFunction;
		}

		status = ListPsNotifyRoutines(&routines, Callback->CallbackAddress, replacedFunction);
	}
	
	return status;
}

/*
* Description:
* RemoveObCallback is responsible to remove a certain callback from the callback list.
*
* Parameters:
* @Callback [KernelCallback*] -- Callback to remove.
*
* Returns:
* @status	[NTSTATUS]		  -- Whether successfuly removed or not.
*/
NTSTATUS RemoveCallback(KernelCallback* Callback) {
	DisabledKernelCallback callback{};
	NTSTATUS status = STATUS_NOT_FOUND;
	
	if (Callback->Type == ObProcessType || Callback->Type == ObThreadType) {
		PFULL_OBJECT_TYPE objectType = NULL;
		ULONG64 operationAddress = 0;

		switch (Callback->Type) {
		case ObProcessType:
			objectType = (PFULL_OBJECT_TYPE)*PsProcessType;
			break;
		case ObThreadType:
			objectType = (PFULL_OBJECT_TYPE)*PsThreadType;
			break;
		}

		ExAcquirePushLockExclusive((PULONG_PTR)&objectType->TypeLock);
		POB_CALLBACK_ENTRY currentObjectCallback = (POB_CALLBACK_ENTRY)(&objectType->CallbackList);

		do {
			if (currentObjectCallback->Enabled) {
				if ((ULONG64)currentObjectCallback->PreOperation == Callback->CallbackAddress) {
					operationAddress = (ULONG64)currentObjectCallback->PreOperation;
					currentObjectCallback->PreOperation = ObPreOpenDummyFunction;
				}
				else if ((ULONG64)currentObjectCallback->PostOperation == Callback->CallbackAddress) {
					operationAddress = (ULONG64)currentObjectCallback->PostOperation;
					currentObjectCallback->PostOperation = ObPostOpenDummyFunction;
				}

				if (operationAddress) {
					callback.CallbackAddress = operationAddress;
					callback.Entry = (ULONG64)currentObjectCallback->Entry;
					callback.Type = Callback->Type;
					break;
				}
			}
			currentObjectCallback = (POB_CALLBACK_ENTRY)currentObjectCallback->CallbackList.Flink;
		} while ((PVOID)currentObjectCallback != (PVOID)(&objectType->CallbackList));

		ExReleasePushLockExclusive((PULONG_PTR)&objectType->TypeLock);
	}
	else if (Callback->Type == PsCreateProcessType || Callback->Type == PsCreateProcessTypeEx) {
		PsRoutinesList routines{};
		ULONG64 replacerFunction = 0;
		routines.Type = Callback->Type;

		switch (Callback->Type) {
		case PsCreateProcessType:
			replacerFunction = (ULONG64)CreateProcessNotifyDummyFunction;
		case PsCreateProcessTypeEx:
			replacerFunction = (ULONG64)CreateProcessNotifyExDummyFunction;
		}

		status = ListPsNotifyRoutines(&routines, replacerFunction, Callback->CallbackAddress);
		callback.CallbackAddress = Callback->CallbackAddress;
		callback.Type = Callback->Type;
	}

	if (NT_SUCCESS(status)) {
		AutoLock locker(aaGlobals.Lock);
		status = AddDisabledCallback(callback);
	}
	
	return status;
}

/*
* Description:
* ListPsNotifyRoutines is responsible to list all registered PsNotify routines.
*
* Parameters:
* @Callbacks	    [CallbacksList*] -- All callbacks as list.
* @ReplacerFunction [ULONG64]		 -- If not null, the address of the function to replace.
* @ReplacedFunction [ULONG64]		 -- If not null, the address of the function to be replaced.
*
* Returns:
* @status		    [NTSTATUS]		 -- Whether successfuly listed or not.
*/
NTSTATUS ListPsNotifyRoutines(PsRoutinesList* Callbacks, ULONG64 ReplacerFunction, ULONG64 ReplacedFunction) {
	NTSTATUS status = STATUS_SUCCESS;
	PVOID searchedRoutineAddress = NULL;
	UCHAR* targetFunctionSignature = NULL;
	UCHAR* listSignature = NULL;
	UCHAR* listCountSignature = NULL;
	ULONG foundIndex = 0;
	SIZE_T targetFunctionDistance = 0;
	SIZE_T listDistance = 0;
	SIZE_T targetFunctionSigLen = 0;
	SIZE_T listSigLen = 0;
	SIZE_T listCountSigLen = 0;
	SIZE_T countOffset = 0;
	ULONG64 currentRoutine = 0;
	
	CHAR driverName[MAX_DRIVER_PATH] = { 0 };

	switch (Callbacks->Type) {
	case PsCreateProcessTypeEx:
	case PsCreateProcessType: {
		targetFunctionSigLen = sizeof(PspSetCreateProcessNotifyRoutineSignature);
		targetFunctionSignature = (UCHAR*)ExAllocatePoolWithTag(PagedPool, targetFunctionSigLen, DRIVER_TAG);

		if (!targetFunctionSignature) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		
		RtlCopyMemory(targetFunctionSignature, PspSetCreateProcessNotifyRoutineSignature, targetFunctionSigLen);
		searchedRoutineAddress = (PVOID)PsSetCreateProcessNotifyRoutineEx;
		targetFunctionDistance = PspSetCreateProcessNotifyRoutineSignatureDistance;

		listSigLen = sizeof(PspCreateProcessNotifyRoutineSignature);
		listSignature = (UCHAR*)ExAllocatePoolWithTag(PagedPool, listSigLen, DRIVER_TAG);

		if (!listSignature) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		RtlCopyMemory(listSignature, PspCreateProcessNotifyRoutineSignature, listSigLen);
		listDistance = PspCreateProcessNotifyRoutineDistance;

		listCountSigLen = sizeof(PspCreateProcessNotifyRoutineCountExSignature);
		listCountSignature = (UCHAR*)ExAllocatePoolWithTag(PagedPool, listCountSigLen, DRIVER_TAG);

		if (!listCountSignature) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		RtlCopyMemory(listCountSignature, PspCreateProcessNotifyRoutineCountExSignature, listCountSigLen);
		countOffset = PsNotifyRoutinesRoutineCountOffsetEx;
		break;
	}
	default:
		status = STATUS_INVALID_PARAMETER;
		break;
	}

	if (!NT_SUCCESS(status))
		goto Cleanup;

	// Find offset of PspCreateProcessNotifyRoutine
	PLONG searchedRoutineOffset = (PLONG)FindPattern((PCUCHAR)targetFunctionSignature, 0xCC, targetFunctionSigLen - 1, searchedRoutineAddress, targetFunctionDistance, &foundIndex, targetFunctionSigLen - 1);

	if (!searchedRoutineOffset)
		return STATUS_NOT_FOUND;

	searchedRoutineAddress = (PUCHAR)searchedRoutineAddress + *(searchedRoutineOffset) + foundIndex + PsNotifyRoutinesRoutineOffset;

	PLONG routinesListOffset = (PLONG)FindPattern((PCUCHAR)listSignature, 0xCC, listSigLen - 1, searchedRoutineAddress, listDistance, &foundIndex, listSigLen);

	if (!routinesListOffset)
		return STATUS_NOT_FOUND;
	PUCHAR routinesList = (PUCHAR)searchedRoutineAddress + *(routinesListOffset) + foundIndex + RoutinesListOffset;

	PLONG routinesLengthOffset = (PLONG)FindPattern((PCUCHAR)listCountSignature, 0xCC, listCountSigLen - 1, searchedRoutineAddress, listDistance, &foundIndex, listCountSigLen - 1);

	if (!routinesLengthOffset)
		return STATUS_NOT_FOUND;

	if (Callbacks->Type == PsCreateProcessType)
		countOffset = PsNotifyRoutinesRoutineCountOffset;
	// Callbacks->NumberOfRoutines = *(PLONG)((PUCHAR)searchedRoutineAddress + *(routinesLengthOffset) + foundIndex + countOffset);
	ULONG routinesCount = *(PLONG)((PUCHAR)searchedRoutineAddress + *(routinesLengthOffset) + foundIndex + countOffset);

	for (SIZE_T i = 0; i < routinesCount; i++) {
		currentRoutine = *(PULONG64)(routinesList + (i * 8));
		currentRoutine &= ~(1ULL << 3) + 1;

		if (ReplacedFunction && ReplacerFunction) {
			if (*(PULONG64)(currentRoutine) == ReplacedFunction)
				*(PULONG64)(currentRoutine) = ReplacerFunction;
		}
		else {
			Callbacks->Routines[i].CallbackAddress = *(PULONG64)(currentRoutine);

			if (NT_SUCCESS(MatchCallback((PVOID)Callbacks->Routines[i].CallbackAddress, driverName)))
				strcpy_s(Callbacks->Routines[i].DriverName, driverName);
		}
	}

	if (!ReplacedFunction && !ReplacerFunction)
		Callbacks->NumberOfRoutines = routinesCount;

Cleanup:
	if (listCountSignature)
		ExFreePoolWithTag(listCountSignature, DRIVER_TAG);
	if (listSignature)
		ExFreePoolWithTag(listSignature, DRIVER_TAG);
	if (targetFunctionSignature)
		ExFreePoolWithTag(targetFunctionSignature, DRIVER_TAG);
	return status;
}

/*
* Description:
* ListObCallbacks is responsible to list all registered ObCallbacks of certain type.
*
* Parameters:
* @Callbacks [CallbacksList*]	-- All callbacks as list.
*
* Returns:
* @status	 [NTSTATUS]			-- Whether successfuly listed or not.
*/
NTSTATUS ListObCallbacks(ObCallbacksList* Callbacks) {
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
* @driverName [PCHAR]    -- Pointer to the driver name if found, else null.
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

/*
* Description:
* AddDisabledCallback is responsible for adding a disabled callback to the list of disabled callbacks.
*
* Parameters:
* @Callback	  [DisabledKernelCallback] -- Callback to add.
*
* Returns:
* @status	  [NTSTATUS]			   -- STATUS_SUCCESS if succeeded else the error.
*/
NTSTATUS AddDisabledCallback(DisabledKernelCallback Callback) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	for (int i = 0; i < MAX_KERNEL_CALLBACKS; i++) {
		if (!aaGlobals.DisabledCallbacks[i].CallbackAddress) {
			aaGlobals.DisabledCallbacks[i].CallbackAddress = Callback.CallbackAddress;
			aaGlobals.DisabledCallbacks[i].Entry = Callback.Entry;
			aaGlobals.DisabledCallbacks[i].Type = Callback.Type;
			aaGlobals.DisabledCallbacksCount++;
			status = STATUS_SUCCESS;
			break;
		}
	}

	return status;
}

/*
* Description:
* RemoveDisabledCallback is responsible for removing a disabled callback to the list of disabled callbacks.
*
* Parameters:
* @Callback			  [KernelCallback*]	  -- Callback to search.
* @DisabledCallback	  [DisabledCallback*] -- Output callback.
*
* Returns:
* @status			  [NTSTATUS]		  -- STATUS_SUCCESS if succeeded else the error.
*/
NTSTATUS RemoveDisabledCallback(KernelCallback* Callback, DisabledKernelCallback* DisabledCallback) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	for (int i = 0; i < aaGlobals.DisabledCallbacksCount; i++) {
		if (aaGlobals.DisabledCallbacks[i].CallbackAddress == Callback->CallbackAddress) {
			DisabledCallback->CallbackAddress = aaGlobals.DisabledCallbacks[i].CallbackAddress;
			DisabledCallback->Entry = aaGlobals.DisabledCallbacks[i].Entry;
			DisabledCallback->Type = aaGlobals.DisabledCallbacks[i].Type;
			aaGlobals.DisabledCallbacksCount--;
			status = STATUS_SUCCESS;
			break;
		}
	}

	return status;
}


/*
* Description:
* ObPreOpenDummyFunction is a dummy function for pre ob callbacks.
*
* Parameters:
* @RegistrationContext [PVOID]						   -- Unused.
* @Info				   [POB_PRE_OPERATION_INFORMATION] -- Unused.
*
* Returns:
* @status			   [NTSTATUS]					   -- Always OB_PREOP_SUCCESS.
*/
OB_PREOP_CALLBACK_STATUS ObPreOpenDummyFunction(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info) {
	return OB_PREOP_SUCCESS;
}

/*
* Description:
* ObPostOpenDummyFunction is a dummy function for post ob callbacks.
*
* Parameters:
* @RegistrationContext [PVOID]						    -- Unused.
* @Info				   [POB_POST_OPERATION_INFORMATION] -- Unused.
*
* Returns:
* There is no return value.
*/
VOID ObPostOpenDummyFunction(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION Info) {
	return;
}

/*
* Description:
* CreateProcessNotifyExDummyFunction is a dummy function for create process notify routine ex.
*
* Parameters:
* @Process    [PEPROCESS]			   -- Unused.
* @ProcessId  [HANDLE]			       -- Unused.
* @CreateInfo [PPS_CREATE_NOTIFY_INFO] -- Unused.
*
* Returns:
* There is no return value.
*/
void CreateProcessNotifyExDummyFunction(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
	return;
}

/*
* Description:
* CreateProcessNotifyDummyFunction is a dummy function for create process notify routine.
*
* Parameters:
* @ParentId  [HANDLE]  -- Unused.
* @ProcessId [HANDLE]  -- Unused.
* @Create	 [BOOLEAN] -- Unused.
*
* Returns:
* There is no return value.
*/
void CreateProcessNotifyDummyFunction(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create) {
	return;
}
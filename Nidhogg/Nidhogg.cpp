#include "pch.h"
#include "Nidhogg.h"

/*
* Description:
* DriverEntry starts the driver directly or creates it for reflective loading.
*
* Parameters:
* @DriverObject [PDRIVER_OBJECT]  -- The driver object supplied by the I/O manager.
* @RegistryPath [PUNICODE_STRING] -- The driver's service registry path.
*
* Returns:
* @status [NTSTATUS] -- Whether driver initialization succeeded.
*/
extern "C"
_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
#ifdef DRIVER_REFLECTIVELY_LOADED
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	Features.DriverReflectivelyLoaded = true;
	Features.ProcessProtection = false;
	Features.ThreadProtection = false;
	Features.RegistryFeatures = false;
	Features.AutoModuleUnload = false;
	Features.FltEnabled = false;
	NidhoggLogger.Info(DRIVER_PREFIX "Driver is being reflectively loaded...\n");

	UNICODE_STRING driverName = RTL_CONSTANT_STRING(DRIVER_NAME);
	UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"IoCreateDriver");
	tIoCreateDriver IoCreateDriver = (tIoCreateDriver)MmGetSystemRoutineAddress(&routineName);

	if (!IoCreateDriver)
		return STATUS_INCOMPATIBLE_DRIVER_BLOCKED;

	NTSTATUS status = IoCreateDriver(&driverName, &NidhoggEntry);

	if (!NT_SUCCESS(status))
		NidhoggLogger.Error(DRIVER_PREFIX "Failed to create driver: (0x%08X)\n", status);
	return status;
#endif

	return NidhoggEntry(DriverObject, RegistryPath);
}

/*
* Description:
* NidhoggEntry is responsible for handling the driver loading process.
*
* Parameters:
* @DriverObject [PDRIVER_OBJECT]  -- The driver object contains a lot of important driver configuration such as DeviceObject, MajorFunctions and more.
* @RegistryPath [PUNICODE_STRING] -- The driver's associated registry path used for filter setup.
*
* Returns:
* @status		[NTSTATUS]		  -- Whether the driver is loaded successfuly or not.
*/
_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NidhoggEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	NTSTATUS status = STATUS_SUCCESS;
	NidhoggDriverObject = DriverObject;
	NidhoggFilter = nullptr;
	NidhoggTeardownStarted = 0;

	if (!InitializeFeatures()) {
		ClearAll();
		return STATUS_INCOMPATIBLE_DRIVER_BLOCKED;
	}

	// Setting up the device object.
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DRIVER_DEVICE_NAME);
	UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(DRIVER_SYMBOLIC_LINK);
	UNICODE_STRING altitude = RTL_CONSTANT_STRING(OB_CALLBACKS_ALTITUDE);
	UNICODE_STRING regAltitude = RTL_CONSTANT_STRING(REG_CALLBACK_ALTITUDE);
	PDEVICE_OBJECT DeviceObject = nullptr;

	// Creating device and symbolic link.
	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);

	if (!NT_SUCCESS(status)) {
		NidhoggLogger.Error(DRIVER_PREFIX "Failed to create device: (0x%08X)\n", status);
		ClearAll();
		return status;
	}

	status = IoCreateSymbolicLink(&symbolicLink, &deviceName);

	if (!NT_SUCCESS(status)) {
		NidhoggLogger.Error(DRIVER_PREFIX "Failed to create symbolic link: (0x%08X)\n", status);
		IoDeleteDevice(DeviceObject);
		ClearAll();
		return status;
	}
	DeviceObject->Flags |= DO_BUFFERED_IO;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = NidhoggCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NidhoggDeviceControl;

	// Registering the process callback function only if the driver isn't reflectively loaded (to avoid BSOD).
	if (!Features.DriverReflectivelyLoaded) {
		OB_OPERATION_REGISTRATION operations[] = {
		{
			PsProcessType,
			OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
			OnPreOpenProcess, nullptr
		},
		{
			PsThreadType,
			OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
			OnPreOpenThread, nullptr
		}
		};
		OB_CALLBACK_REGISTRATION registrationCallbacks = {
			OB_FLT_REGISTRATION_VERSION,
			REGISTERED_OB_CALLBACKS,
			RTL_CONSTANT_STRING(OB_CALLBACKS_ALTITUDE),
			nullptr,
			operations
		};

		status = ObRegisterCallbacks(&registrationCallbacks, &RegistrationHandle);

		if (!NT_SUCCESS(status)) {
			NidhoggLogger.Error(DRIVER_PREFIX "Failed to register process callback: (0x%08X)\n", status);
			status = STATUS_SUCCESS;
			Features.ProcessProtection = false;
			Features.ThreadProtection = false;
		}

		status = CmRegisterCallbackEx(OnRegistryNotify, &regAltitude, DriverObject, nullptr, &NidhoggRegistryHandler->regCookie, nullptr);

		if (!NT_SUCCESS(status)) {
			NidhoggLogger.Error(DRIVER_PREFIX "Failed to register registry callback: (0x%08X)\n", status);
			status = STATUS_SUCCESS;
			Features.RegistryFeatures = false;
		}

		status = PsSetCreateProcessNotifyRoutine(OnProcessCreationExit, FALSE);

		if (!NT_SUCCESS(status)) {
			NidhoggLogger.Error(DRIVER_PREFIX "Failed to register process creation callback: (0x%08X)\n", status);
			status = STATUS_SUCCESS;
			Features.AutoModuleUnload = false;
		}
	}
	if (Features.FltEnabled) {
		status = SetFilterRegistryKey(RegistryPath);
		if (NT_SUCCESS(status))
			status = FltRegisterFilter(DriverObject, &NidhoggFilterRegistration, &NidhoggFilter);

		if (NT_SUCCESS(status)) {
			status = FltStartFiltering(NidhoggFilter);

			if (!NT_SUCCESS(status)) {
				FltUnregisterFilter(NidhoggFilter);
				NidhoggFilter = nullptr;
			}
		}

		if (!NT_SUCCESS(status)) {
			NidhoggLogger.Warning(DRIVER_PREFIX "Filter Manager startup failed (0x%08X); using NTFS hook fallback.\n", status);
			Features.FltEnabled = false;
			if (!reinterpret_cast<PULONG>(ObReferenceObjectByName))
				Features.FileProtection = false;
			status = STATUS_SUCCESS;
		}
	}
	if (!Features.FltEnabled)
		DriverObject->DriverUnload = NidhoggUnload;
	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	NidhoggLogger.Info(DRIVER_PREFIX "Initialization finished.\n");
	return status;
}

/*
* Description:
* NidhoggUnload is responsible for handling the driver unloading process which includes: Removing all hooks, deleting the symbolic link and the deviceobject.
*
* Parameters:
* @DriverObject [PDRIVER_OBJECT] -- The driver object contains a lot of important driver configuration such as DeviceObject, MajorFunctions and more.
*
* Returns:
* There is no return value.
*/
_Function_class_(DRIVER_UNLOAD)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
void NidhoggUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	if (InterlockedCompareExchange(&NidhoggTeardownStarted, 1, 0) != 0)
		return;

	NidhoggLogger.Info(DRIVER_PREFIX "Unloading...\n");
	if (NidhoggFilter) {
		FltUnregisterFilter(NidhoggFilter);
		NidhoggFilter = nullptr;
	}

	if (NidhoggRegistryHandler && NidhoggRegistryHandler->regCookie.QuadPart != 0) {
		NTSTATUS status = CmUnRegisterCallback(NidhoggRegistryHandler->regCookie);

		if (!NT_SUCCESS(status)) {
			NidhoggLogger.Error(DRIVER_PREFIX "Failed to unregister registry callbacks: (0x%08X)\n", status);
		}
	}

	if (Features.AutoModuleUnload) {
		NTSTATUS status = PsSetCreateProcessNotifyRoutine(OnProcessCreationExit, TRUE);

		if (!NT_SUCCESS(status)) {
			NidhoggLogger.Error(DRIVER_PREFIX "Failed to unregister process creation callback: (0x%08X)\n", status);
		}
	}

	if (RegistrationHandle) {
		ObUnRegisterCallbacks(RegistrationHandle);
		RegistrationHandle = NULL;
	}
	ClearAll();

	UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(DRIVER_SYMBOLIC_LINK);
	IoDeleteSymbolicLink(&symbolicLink);

	if (DriverObject->DeviceObject) {
		IoDeleteDevice(DriverObject->DeviceObject);
	}
}

/*
* Description:
* ClearAll is responsible for freeing all allocated memory and cleaning all the globals.
*
* Parameters:
* There are no parameters.
*
* Returns:
* There is no return value.
*/
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
void ClearAll() {
	if (NidhoggNetworkHandler) {
		NidhoggLogger.Debug(DRIVER_PREFIX "Deleting NetworkHandler...\n");
		delete NidhoggNetworkHandler;
		NidhoggNetworkHandler = nullptr;
	}
	
	if (NidhoggRegistryHandler) {
		NidhoggLogger.Debug(DRIVER_PREFIX "Deleting RegistryHandler...\n");
		delete NidhoggRegistryHandler;
		NidhoggRegistryHandler = nullptr;
	}
	
	if (NidhoggAntiAnalysisHandler) {
		NidhoggLogger.Debug(DRIVER_PREFIX "Deleting AntiAnalysisHandler...\n");
		delete NidhoggAntiAnalysisHandler;
		NidhoggAntiAnalysisHandler = nullptr;
	}
	
	if (NidhoggMemoryHandler) {
		NidhoggLogger.Debug(DRIVER_PREFIX "Deleting MemoryHandler...\n");
		delete NidhoggMemoryHandler;
		NidhoggMemoryHandler = nullptr;
	}
	
	if (NidhoggFileHandler) {
		NidhoggLogger.Debug(DRIVER_PREFIX "Deleting FileHandler...\n");
		delete NidhoggFileHandler;
		NidhoggFileHandler = nullptr;
	}
	
	if (NidhoggThreadHandler) {
		NidhoggLogger.Debug(DRIVER_PREFIX "Deleting ThreadHandler...\n");
		delete NidhoggThreadHandler;
		NidhoggThreadHandler = nullptr;
	}
	
	if (NidhoggProcessHandler) {
		NidhoggLogger.Debug(DRIVER_PREFIX "Deleting ProcessHandler...\n");
		delete NidhoggProcessHandler;
		NidhoggProcessHandler = nullptr;
	}
	
	NidhoggLogger.Info(DRIVER_PREFIX "All handlers cleared successfully\n");
}

/*
* Description:
* InitializeFeatures is responsible for initializing the features and the globals.
*
* Parameters:
* There are no parameters.
*
* Returns:
* There is no return value.
*/
_IRQL_requires_max_(APC_LEVEL)
bool InitializeFeatures() {
	NidhoggProcessHandler = nullptr;
	NidhoggThreadHandler = nullptr;
	NidhoggFileHandler = nullptr;
	NidhoggMemoryHandler = nullptr;
	NidhoggAntiAnalysisHandler = nullptr;
	NidhoggRegistryHandler = nullptr;
	NidhoggNetworkHandler = nullptr;
	
	// Get windows version.
	RTL_OSVERSIONINFOW osVersion = { sizeof(osVersion) };
	NTSTATUS result = RtlGetVersion(&osVersion);

	if (!NT_SUCCESS(result))
		return false;

	WindowsBuildNumber = osVersion.dwBuildNumber;

	if (WindowsBuildNumber < WIN_1507)
		return false;

	UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ExAllocatePool2");
	AllocatePool2 = reinterpret_cast<decltype(ExAllocatePool2)*>(MmGetSystemRoutineAddress(&routineName));

	// Initialize utils.
	__try {
		NidhoggProcessHandler = new ProcessHandler();

		if (!NidhoggProcessHandler)
			return false;

		NidhoggThreadHandler = new ThreadHandler();

		if (!NidhoggThreadHandler)
			return false;

		NidhoggFileHandler = new FileHandler();

		if (!NidhoggFileHandler)
			return false;

		NidhoggMemoryHandler = new MemoryHandler();

		if (!NidhoggMemoryHandler)
			return false;

		NidhoggAntiAnalysisHandler = new AntiAnalysisHandler();

		if (!NidhoggAntiAnalysisHandler)
			return false;

		NidhoggRegistryHandler = new RegistryHandler();

		if (!NidhoggRegistryHandler)
			return false;

		NidhoggNetworkHandler = new NetworkHandler();

		if (!NidhoggNetworkHandler)
			return false;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ClearAll();
		return false;
	}

	// Initialize functions.
	if (!reinterpret_cast<PULONG>(MmCopyVirtualMemory))
		Features.ReadData = false;

	if (!reinterpret_cast<PULONG>(ZwProtectVirtualMemory) || !Features.ReadData)
		Features.WriteData = false;

	if (!Features.WriteData || !reinterpret_cast<PULONG>(PsGetProcessPeb))
		Features.FunctionPatching = false;

	if (!reinterpret_cast<PULONG>(PsGetProcessPeb) || !reinterpret_cast<PULONG>(PsLoadedModuleList) || 
		!&PsLoadedModuleResource)
		Features.ModuleHiding = false;

	if (!Features.FltEnabled && !reinterpret_cast<PULONG>(ObReferenceObjectByName))
		Features.FileProtection = false;

	if (!reinterpret_cast<PULONG>(KeInsertQueueApc))
		Features.EtwTiTamper = false;

	if (!reinterpret_cast<PULONG>(KeInitializeApc) || !reinterpret_cast<PULONG>(KeInsertQueueApc) || 
		!reinterpret_cast<PULONG>(KeTestAlertThread) || !reinterpret_cast<PULONG>(ZwQuerySystemInformation))
		Features.ApcInjection = false;
	return true;
}

/*
* Description:
* NidhoggFilterUnload releases filter and driver resources when Filter Manager unloads the minifilter.
*
* Parameters:
* @Flags [FLT_FILTER_UNLOAD_FLAGS] -- Flags supplied by Filter Manager.
*
* Returns:
* @status [NTSTATUS] -- STATUS_SUCCESS after cleanup.
*/
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NidhoggFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
	UNREFERENCED_PARAMETER(Flags);
	NidhoggUnload(NidhoggDriverObject);
	return STATUS_SUCCESS;
}

/*
* Description:
* NidhoggInstanceSetup limits file protection to NTFS volumes.
*
* Parameters:
* @FltObjects           [PCFLT_RELATED_OBJECTS] -- Related filter objects, unused.
* @Flags                [FLT_INSTANCE_SETUP_FLAGS] -- Instance setup flags, unused.
* @VolumeDeviceType     [DEVICE_TYPE] -- Volume device type, unused.
* @VolumeFilesystemType [FLT_FILESYSTEM_TYPE] -- File system type of the volume.
*
* Returns:
* @status [NTSTATUS] -- Whether Filter Manager should attach to the volume.
*/
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NidhoggInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType) {
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	return VolumeFilesystemType == FLT_FSTYPE_NTFS ? STATUS_SUCCESS : STATUS_FLT_DO_NOT_ATTACH;
}

/*
* Description:
* SetFilterRegistryKey registers the default minifilter instance without an INF.
*
* Parameters:
* @RegistryPath [PUNICODE_STRING] -- The driver's service registry path.
*
* Returns:
* @status [NTSTATUS] -- Whether all instance values were written.
*/
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SetFilterRegistryKey(_In_ PUNICODE_STRING RegistryPath) {
	if (!RegistryPath || !RegistryPath->Buffer)
		return STATUS_INVALID_PARAMETER;

	HANDLE serviceKey = nullptr;
	HANDLE parametersKey = nullptr;
	HANDLE instancesKey = nullptr;
	HANDLE instanceKey = nullptr;
	OBJECT_ATTRIBUTES attributes = {};
	UNICODE_STRING parametersName = RTL_CONSTANT_STRING(L"Parameters");
	UNICODE_STRING instancesName = RTL_CONSTANT_STRING(L"Instances");
	UNICODE_STRING instanceName = RTL_CONSTANT_STRING(FILE_FILTER_INSTANCE_NAME);
	UNICODE_STRING defaultValue = RTL_CONSTANT_STRING(L"DefaultInstance");
	UNICODE_STRING altitudeValue = RTL_CONSTANT_STRING(L"Altitude");
	UNICODE_STRING flagsValue = RTL_CONSTANT_STRING(L"Flags");
	ULONG flags = 0;
	NTSTATUS status = STATUS_SUCCESS;

	InitializeObjectAttributes(&attributes, RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
	status = ZwOpenKey(&serviceKey, KEY_CREATE_SUB_KEY | KEY_SET_VALUE, &attributes);

	if (!NT_SUCCESS(status))
		return status;

	HANDLE parentKey = serviceKey;
	if (WindowsBuildNumber >= WIN_11_24H2) {
		InitializeObjectAttributes(&attributes, &parametersName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			serviceKey, nullptr);
		status = ZwCreateKey(&parametersKey, KEY_CREATE_SUB_KEY | KEY_SET_VALUE, &attributes,
			0, nullptr, REG_OPTION_NON_VOLATILE, nullptr);
		if (!NT_SUCCESS(status))
			goto Cleanup;
		parentKey = parametersKey;
	}

	InitializeObjectAttributes(&attributes, &instancesName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		parentKey, nullptr);
	status = ZwCreateKey(&instancesKey, KEY_CREATE_SUB_KEY | KEY_SET_VALUE, &attributes,
		0, nullptr, REG_OPTION_NON_VOLATILE, nullptr);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	status = ZwSetValueKey(instancesKey, &defaultValue, 0, REG_SZ,
		const_cast<WCHAR*>(FILE_FILTER_INSTANCE_NAME), sizeof(FILE_FILTER_INSTANCE_NAME));
	if (!NT_SUCCESS(status))
		goto Cleanup;

	InitializeObjectAttributes(&attributes, &instanceName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		instancesKey, nullptr);
	status = ZwCreateKey(&instanceKey, KEY_SET_VALUE, &attributes,
		0, nullptr, REG_OPTION_NON_VOLATILE, nullptr);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	status = ZwSetValueKey(instanceKey, &altitudeValue, 0, REG_SZ,
		const_cast<WCHAR*>(FILE_FILTER_ALTITUDE), sizeof(FILE_FILTER_ALTITUDE));
	if (NT_SUCCESS(status))
		status = ZwSetValueKey(instanceKey, &flagsValue, 0, REG_DWORD, &flags, sizeof(flags));

Cleanup:
	if (instanceKey)
		ZwClose(instanceKey);
	if (instancesKey)
		ZwClose(instancesKey);
	if (parametersKey)
		ZwClose(parametersKey);
	ZwClose(serviceKey);
	return status;
}

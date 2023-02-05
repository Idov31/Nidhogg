#pragma once
#include "pch.h"

// Prototypes
bool FindFile(WCHAR* path);
bool AddFile(WCHAR* path);
bool RemoveFile(WCHAR* path);
NTSTATUS HookedNtfsIrpCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS InstallNtfsHook(int irpMjFunction);
NTSTATUS UninstallNtfsHook(int irpMjFunction);

NTSTATUS HookedNtfsIrpCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	WCHAR fullPath[MAX_PATH + 1] = L"C:";
	auto stack = IoGetCurrentIrpStackLocation(Irp);

	if (!stack || !stack->FileObject)
		return ((tNtfsIrpFunction)fGlobals.Callbacks[0].Address)(DeviceObject, Irp);

	if (stack->FileObject->FileName.Length == 0)
		return ((tNtfsIrpFunction)fGlobals.Callbacks[0].Address)(DeviceObject, Irp);

	wcscat(fullPath, stack->FileObject->FileName.Buffer);

	AutoLock locker(fGlobals.Lock);

	if (FindFile(fullPath)) {
		Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
		return STATUS_SUCCESS;
	}

	return ((tNtfsIrpFunction)fGlobals.Callbacks[0].Address)(DeviceObject, Irp);
}

NTSTATUS InstallNtfsHook(int irpMjFunction) {
	UNICODE_STRING ntfsName;
	PDRIVER_OBJECT ntfsDriverObject;
	NTSTATUS status = STATUS_SUCCESS;

	// InterlockedExchange64 maybe a problem and will need to use InterlockedExchange.
	RtlInitUnicodeString(&ntfsName, L"\\FileSystem\\NTFS");
	status = dimGlobals.ObReferenceObjectByName(&ntfsName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&ntfsDriverObject);

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "Failed to get ntfs driver object, (0x%08X).\n", status));
		return status;
	}

	switch (irpMjFunction) {
	case IRP_MJ_CREATE: {
		fGlobals.Callbacks[0].Address = (PVOID)InterlockedExchange64((LONG64*)&ntfsDriverObject->MajorFunction[IRP_MJ_CREATE], (LONG64)HookedNtfsIrpCreate);
		fGlobals.Callbacks[0].Activated = true;
		KdPrint((DRIVER_PREFIX "Switched addresses\n"));
		break;
	}
	default:
		status = STATUS_NOT_SUPPORTED;
	}

	ObDereferenceObject(ntfsDriverObject);
	return status;
}

NTSTATUS UninstallNtfsHook(int irpMjFunction) {
	UNICODE_STRING ntfsName;
	PDRIVER_OBJECT ntfsDriverObject;
	NTSTATUS status = STATUS_SUCCESS;

	RtlInitUnicodeString(&ntfsName, L"\\FileSystem\\NTFS");

	status = dimGlobals.ObReferenceObjectByName(&ntfsName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&ntfsDriverObject);

	if (!NT_SUCCESS(status))
		return status;

	switch (irpMjFunction) {
	case IRP_MJ_CREATE: {
		InterlockedExchange64((LONG64*)&ntfsDriverObject->MajorFunction[irpMjFunction], (LONG64)fGlobals.Callbacks[0].Address);
		fGlobals.Callbacks[0].Address = nullptr;
		fGlobals.Callbacks[0].Activated = false;
		break;
	}
	default:
		status = STATUS_NOT_SUPPORTED;
	}

	ObDereferenceObject(ntfsDriverObject);
	
	return status;
}


/*
* Description:
* FindFile is responsible for searching if a file exists in the protected files list.
*
* Parameters:
* @path   [WCHAR*] -- File's path.
*
* Returns:
* @status [bool]   -- Whether found or not.
*/
bool FindFile(WCHAR* path) {
	for (int i = 0; i < fGlobals.Files.FilesCount; i++)
		if (_wcsicmp(fGlobals.Files.FilesPath[i], path) == 0)
			return true;
	return false;
}

/*
* Description:
* AddFile is responsible for adding a file to the protected files list.
*
* Parameters:
* @path   [WCHAR*] -- File's path.
*
* Returns:
* @status [bool]   -- Whether successfully added or not.
*/
bool AddFile(WCHAR* path) {
	for (int i = 0; i < MAX_FILES; i++)
		if (fGlobals.Files.FilesPath[i] == nullptr) {
			auto len = (wcslen(path) + 1) * sizeof(WCHAR);
			auto buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, len, DRIVER_TAG);

			// Not enough resources.
			if (!buffer) {
				break;
			}

			wcscpy_s(buffer, len / sizeof(WCHAR), path);
			fGlobals.Files.FilesPath[i] = buffer;
			fGlobals.Files.FilesCount++;
			return true;
		}
	return false;
}

/*
* Description:
* RemoveFile is responsible for removing a file to the protected files list.
*
* Parameters:
* @path   [WCHAR*] -- File's path.
*
* Returns:
* @status [bool]   -- Whether successfully removed or not.
*/
bool RemoveFile(WCHAR* path) {
	for (int i = 0; i < fGlobals.Files.FilesCount; i++)
		if (_wcsicmp(fGlobals.Files.FilesPath[i], path) == 0) {
			ExFreePoolWithTag(fGlobals.Files.FilesPath[i], DRIVER_TAG);
			fGlobals.Files.FilesPath[i] = nullptr;
			fGlobals.Files.FilesCount--;
			return true;
		}
	return false;
}

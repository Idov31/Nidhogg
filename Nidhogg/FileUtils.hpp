#pragma once
#include "pch.h"

// Prototypes
bool FindFile(WCHAR* path);
bool AddFile(WCHAR* path);
bool RemoveFile(WCHAR* path);

OB_PREOP_CALLBACK_STATUS OnPreFileOperation(PVOID /* RegistrationContext */, POB_PRE_OPERATION_INFORMATION Info) {
	POBJECT_NAME_INFORMATION ObjectNameInfo;
	UNICODE_STRING filePath;
	NTSTATUS status = STATUS_SUCCESS;

	if (Info->ObjectType != *IoFileObjectType) {
		return OB_PREOP_SUCCESS;
	}

	if (!Info->Object || !MmIsAddressValid(Info->Object)) {
		return OB_PREOP_SUCCESS;
	}

	PFILE_OBJECT FileObject = (PFILE_OBJECT)Info->Object;

	if (!FileObject->FileName.Buffer || !MmIsAddressValid(FileObject->FileName.Buffer) ||
		!FileObject->DeviceObject || !MmIsAddressValid(FileObject->DeviceObject)) {
		return OB_PREOP_SUCCESS;
	}

	status = IoQueryFileDosDeviceName(FileObject, &ObjectNameInfo);

	if (!NT_SUCCESS(status)) {
		return OB_PREOP_SUCCESS;
	}

	if (!ObjectNameInfo->Name.Buffer || !MmIsAddressValid(ObjectNameInfo->Name.Buffer))
		return OB_PREOP_SUCCESS;

	filePath = ObjectNameInfo->Name;
	AutoLock locker(fGlobals.Lock);

	// Removing write and delete permissions.
	if (FindFile(filePath.Buffer)) {
		FileObject->DeleteAccess = FALSE;
		FileObject->DeletePending = FALSE;
		FileObject->SharedDelete = FALSE;
		FileObject->WriteAccess = FALSE;
		FileObject->SharedWrite = FALSE;
	}

	ExFreePool(ObjectNameInfo);
	return OB_PREOP_SUCCESS;
}

bool FindFile(WCHAR* path) {
	for (int i = 0; i < fGlobals.FilesCount; i++)
		if (_wcsicmp(fGlobals.Files[i], path) == 0)
			return true;
	return false;
}

bool AddFile(WCHAR* path) {
	for (int i = 0; i < MAX_FILES; i++)
		if (fGlobals.Files[i] == nullptr) {
			auto len = (wcslen(path) + 1) * sizeof(WCHAR);
			auto buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, len, DRIVER_TAG);

			// Not enough resources.
			if (!buffer) {
				break;
			}

			wcscpy_s(buffer, len / sizeof(WCHAR), path);
			fGlobals.Files[i] = buffer;
			fGlobals.FilesCount++;
			return true;
		}
	return false;
}

bool RemoveFile(WCHAR* path) {
	for (int i = 0; i < fGlobals.FilesCount; i++)
		if (_wcsicmp(fGlobals.Files[i], path) == 0) {
			ExFreePoolWithTag(fGlobals.Files[i], DRIVER_TAG);
			fGlobals.Files[i] = nullptr;
			fGlobals.FilesCount--;
			return true;
		}
	return false;
}

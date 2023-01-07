#pragma once
#include "pch.h"

// Definitions.
PVOID GetModuleBase(PEPROCESS Process, WCHAR* moduleName);
PVOID GetFunctionAddress(PVOID moduleBase, CHAR* functionName);
NTSTATUS KeWriteProcessMemory(PVOID sourceDataAddress, PEPROCESS TargetProcess, PVOID targetAddress, SIZE_T dataSize, MODE mode);
NTSTATUS KeReadProcessMemory(PEPROCESS Process, PVOID sourceAddress, PVOID targetAddress, SIZE_T dataSize, MODE mode);

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
	status = ObOpenObjectByPointer(TargetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, UserMode, &hTargetProcess);

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
	if (ObOpenObjectByPointer(TargetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, UserMode, &hTargetProcess) == STATUS_SUCCESS) {
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

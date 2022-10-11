#pragma once
#include "pch.h"

/*
* Description:
* OnImageLoad is responsible for handling any kind of loading operations and patching specific functionality if defined.
*
* Parameters:
* @FullImageName [PUNICODE_STRING] -- Image's name.
* @ProcessId	 [HANDLE]		   -- The process id of the process that performs the loading.
* @ImageInfo	 [PIMAGE_INFO]	   -- Various information of the loaded image including if it is user mode or kernel mode, image base, etc.
*
* Returns:
* There is no return value.
*/
void OnImageLoad(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
	HANDLE hTargetProcess;
	PEPROCESS TargetProcess;
	ULONG oldProtection;
	NTSTATUS status;
	SIZE_T outBytes;
	MEMORY_BASIC_INFORMATION memInfo = { 0 };
	bool changeProtection = false;

	// Filter only valid user space processes.
	if (ProcessId == 0 || ImageInfo->SystemModeImage == 1 || FullImageName->Length == 0)
		return;

	if (pmGlobals.ModulesList.PatchedModulesCount == 0)
		return;

	if (dimGlobals.ZwProtectVirtualMemory == NULL)
		return;

	// Attaching to the remote process address space.
	if (PsLookupProcessByProcessId(ProcessId, &TargetProcess) != STATUS_SUCCESS)
		return;
	
	AutoLock lock(pmGlobals.Lock);

	for (int i = 0; i < pmGlobals.ModulesList.PatchedModulesCount; i++) {
		if (wcisstr(FullImageName->Buffer, pmGlobals.ModulesList.Modules[i].ModuleName)) {
			PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ImageInfo->ImageBase;

			// Checking that the image is valid PE file.
			if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
				return;

			PFULL_IMAGE_NT_HEADERS ntHeaders = (PFULL_IMAGE_NT_HEADERS)((PUCHAR)ImageInfo->ImageBase + dosHeader->e_lfanew);

			if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
				return;
			
			IMAGE_OPTIONAL_HEADER optionalHeader = ntHeaders->OptionalHeader;

			if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
				return;

			// Iterating the export directory.
			PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ImageInfo->ImageBase + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

			DWORD* addresses = (DWORD*)((PUCHAR)ImageInfo->ImageBase + exportDirectory->AddressOfFunctions);
			WORD* ordinals = (WORD*)((PUCHAR)ImageInfo->ImageBase + exportDirectory->AddressOfNameOrdinals);
			DWORD* names = (DWORD*)((PUCHAR)ImageInfo->ImageBase + exportDirectory->AddressOfNames);

			for (DWORD j = 0; j < exportDirectory->NumberOfNames; j++) {
				if (_stricmp((char*)((PUCHAR)ImageInfo->ImageBase + names[j]), pmGlobals.ModulesList.Modules[i].FunctionName) == 0) {
					if (ObOpenObjectByPointer(TargetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hTargetProcess) != STATUS_SUCCESS) {
						KdPrint((DRIVER_PREFIX "Failed to get process to handle.\n"));
						break;
					}

					auto patchLen = strlen((char*)pmGlobals.ModulesList.Modules[i].Patch);
					auto functionAddress = (PVOID)((PUCHAR)ImageInfo->ImageBase + addresses[ordinals[j]]);

					// Adding write permissions.
					status = ZwQueryVirtualMemory(hTargetProcess, functionAddress, MemoryBasicInformation, &memInfo, sizeof(MEMORY_BASIC_INFORMATION), &outBytes);
					
					if (status != STATUS_SUCCESS) {
						KdPrint((DRIVER_PREFIX "Failed to query protection, (0x%08X).\n", status));
						ZwClose(hTargetProcess);
						break;
					}
					
					/*KdPrint((DRIVER_PREFIX "Protection of the page is - %d.\n", memInfo.AllocationProtect));
					KdPrint((DRIVER_PREFIX "State of the page is - %d.\n", memInfo.State));
					KdPrint((DRIVER_PREFIX "Type of the page is - %d.\n", memInfo.Type));*/

					changeProtection = memInfo.AllocationProtect != PAGE_EXECUTE_WRITECOPY && memInfo.AllocationProtect != PAGE_EXECUTE_READWRITE;

					if (changeProtection) {
						status = dimGlobals.ZwProtectVirtualMemory(hTargetProcess, &functionAddress, &patchLen, PAGE_EXECUTE_READWRITE, &oldProtection);

						if (status != STATUS_SUCCESS) {
							KdPrint((DRIVER_PREFIX "Failed to change protection, (0x%08X).\n", status));
							ZwClose(hTargetProcess);
							break;
						}
					}
					

					// Patching the function.
					SIZE_T written;
					char patch[6] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
					
					// status = dimGlobals.MmCopyVirtualMemory(PsGetCurrentProcess(), pmGlobals.ModulesList.Modules[i].Patch, Process, functionAddress, patchLen, KernelMode, &written);	
					status = dimGlobals.MmCopyVirtualMemory(PsGetCurrentProcess(), &patch[0], TargetProcess, functionAddress, 6, KernelMode, &written);

					if (status != STATUS_SUCCESS)
						KdPrint((DRIVER_PREFIX "MmCopyVirtualMemory failed status, (0x%08X).\n", status));
					else
						KdPrint((DRIVER_PREFIX "Patched function #5.\n"));

					// Restoring permissions and cleaning up.
					if (changeProtection)
						dimGlobals.ZwProtectVirtualMemory(hTargetProcess, &functionAddress, &patchLen, oldProtection, &oldProtection);

					ZwClose(hTargetProcess);
					KdPrint((DRIVER_PREFIX "Cleaned up #6.\n"));
					break;
				}
			}
		}
	}
	ObDereferenceObject(TargetProcess);
}

/*
* Description:
* FindModule is responsible for searching if a module exists in the list of modules that need to be patched.
*
* Parameters:
* @patchedModule   [PatchedModule&] -- Module's information.
*
* Returns:
* @status [bool]   -- Whether found or not.
*/
bool FindModule(PatchedModule& patchedModule) {
	for (int i = 0; i < pmGlobals.ModulesList.PatchedModulesCount; i++)
		if (_wcsicmp(pmGlobals.ModulesList.Modules[i].ModuleName, patchedModule.ModuleName) == 0 &&
			_stricmp(pmGlobals.ModulesList.Modules[i].FunctionName, patchedModule.FunctionName) == 0)
			return true;
	return false;
}

/*
* Description:
* AddModule is responsible for adding a module to the list of modules that need to be patched.
*
* Parameters:
* @patchedModule [PatchedModule&] -- Module to add.
*
* Returns:
* @status		 [bool]			  -- Whether successfully added or not.
*/
bool AddModule(PatchedModule& patchedModule) {
	
	for (int i = 0; i < MAX_PATCHED_MODULES; i++)
		if (pmGlobals.ModulesList.Modules[i].FunctionName == nullptr) {
			auto functionNameLen = (strlen(patchedModule.FunctionName) + 1) * sizeof(CHAR);
			auto functionNameBuffer = (CHAR*)ExAllocatePoolWithTag(PagedPool, functionNameLen, DRIVER_TAG);

			// Not enough resources.
			if (!functionNameBuffer) {
				break;
			}

			auto moduleNameLen = (wcslen(patchedModule.ModuleName) + 1) * sizeof(WCHAR);
			auto moduleNameBuffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, moduleNameLen, DRIVER_TAG);

			// Not enough resources.
			if (!moduleNameBuffer) {
				ExFreePoolWithTag(functionNameBuffer, DRIVER_TAG);
				break;
			}

			auto patchLen = strlen((char*)patchedModule.Patch) * sizeof(UCHAR);
			auto patchBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, patchLen, DRIVER_TAG);

			// Not enough resources.
			if (!patchBuffer) {
				ExFreePoolWithTag(moduleNameBuffer, DRIVER_TAG);
				ExFreePoolWithTag(functionNameBuffer, DRIVER_TAG);
				break;
			}

			strcpy_s(functionNameBuffer, functionNameLen / sizeof(CHAR), patchedModule.FunctionName);
			wcscpy_s(moduleNameBuffer, moduleNameLen / sizeof(WCHAR), patchedModule.ModuleName);
			memcpy_s(patchBuffer, patchLen, patchedModule.Patch, patchLen);
			pmGlobals.ModulesList.Modules[i].FunctionName = functionNameBuffer;
			pmGlobals.ModulesList.Modules[i].ModuleName = moduleNameBuffer;
			pmGlobals.ModulesList.Modules[i].Patch = patchBuffer;
			pmGlobals.ModulesList.PatchedModulesCount++;

			return true;
		}
	return false;
}

/*
* Description:
* RemoveModule is responsible for removing a module from the list of modules that need to be patched.
*
* Parameters:
* @patchedModule [PatchedModule&] -- Module to add.
*
* Returns:
* @status		 [bool]			  -- Whether successfully removed or not.
*/
bool RemoveModule(PatchedModule& patchedModule) {
	for (int i = 0; i < pmGlobals.ModulesList.PatchedModulesCount; i++)
		if (_wcsicmp(pmGlobals.ModulesList.Modules[i].ModuleName, patchedModule.ModuleName) == 0 &&
			_stricmp(pmGlobals.ModulesList.Modules[i].FunctionName, patchedModule.FunctionName) == 0) {

			ExFreePoolWithTag(pmGlobals.ModulesList.Modules[i].FunctionName, DRIVER_TAG);
			ExFreePoolWithTag(pmGlobals.ModulesList.Modules[i].ModuleName, DRIVER_TAG);
			ExFreePoolWithTag(pmGlobals.ModulesList.Modules[i].Patch, DRIVER_TAG);
			pmGlobals.ModulesList.Modules[i].FunctionName = nullptr;
			pmGlobals.ModulesList.Modules[i].ModuleName = nullptr;
			pmGlobals.ModulesList.Modules[i].Patch = nullptr;
			pmGlobals.ModulesList.PatchedModulesCount--;
			return true;
		}
	return false;
}

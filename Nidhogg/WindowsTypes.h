#pragma once

// Documented.
#define WIN_1507 10240
#define WIN_1511 10586
#define WIN_1607 14393
#define WIN_1703 15063
#define WIN_1709 16299
#define WIN_1803 17134
#define WIN_1809 17763
#define WIN_1903 18362
#define WIN_1909 18363
#define WIN_2004 19041
#define WIN_20H2 19042
#define WIN_21H1 19043
#define WIN_21H2 19044
#define WIN_22H2 19045
#define WIN_1121H2 22000
#define WIN_1122H2 22621

#define IMAGE_DOS_SIGNATURE                 0x5A4D
#define IMAGE_NT_SIGNATURE                  0x00004550

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data

#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

typedef unsigned long       DWORD;
typedef unsigned short      WORD;
typedef unsigned char       BYTE;

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	WORD   e_magic;                     // Magic number
	WORD   e_cblp;                      // Bytes on last page of file
	WORD   e_cp;                        // Pages in file
	WORD   e_crlc;                      // Relocations
	WORD   e_cparhdr;                   // Size of header in paragraphs
	WORD   e_minalloc;                  // Minimum extra paragraphs needed
	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD   e_ss;                        // Initial (relative) SS value
	WORD   e_sp;                        // Initial SP value
	WORD   e_csum;                      // Checksum
	WORD   e_ip;                        // Initial IP value
	WORD   e_cs;                        // Initial (relative) CS value
	WORD   e_lfarlc;                    // File address of relocation table
	WORD   e_ovno;                      // Overlay number
	WORD   e_res[4];                    // Reserved words
	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD   e_oeminfo;                   // OEM information; e_oemid specific
	WORD   e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	ULONG   VirtualAddress;
	ULONG   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD   Characteristics;
	DWORD   TimeDateStamp;
	WORD    MajorVersion;
	WORD    MinorVersion;
	DWORD   Name;
	DWORD   Base;
	DWORD   NumberOfFunctions;
	DWORD   NumberOfNames;
	DWORD   AddressOfFunctions;     // RVA from base of image
	DWORD   AddressOfNames;         // RVA from base of image
	DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
	WORD        Magic;
	BYTE        MajorLinkerVersion;
	BYTE        MinorLinkerVersion;
	DWORD       SizeOfCode;
	DWORD       SizeOfInitializedData;
	DWORD       SizeOfUninitializedData;
	DWORD       AddressOfEntryPoint;
	DWORD       BaseOfCode;
	ULONGLONG   ImageBase;
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
	WORD        MajorOperatingSystemVersion;
	WORD        MinorOperatingSystemVersion;
	WORD        MajorImageVersion;
	WORD        MinorImageVersion;
	WORD        MajorSubsystemVersion;
	WORD        MinorSubsystemVersion;
	DWORD       Win32VersionValue;
	DWORD       SizeOfImage;
	DWORD       SizeOfHeaders;
	DWORD       CheckSum;
	WORD        Subsystem;
	WORD        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	DWORD       LoaderFlags;
	DWORD       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, * PIMAGE_OPTIONAL_HEADER;

typedef struct _FULL_IMAGE_NT_HEADERS {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
} FULL_IMAGE_NT_HEADERS, * PFULL_IMAGE_NT_HEADERS;

#pragma warning(default : 4214)

enum LDR_DDAG_STATE
{
	LdrModulesMerged = -5,
	LdrModulesInitError = -4,
	LdrModulesSnapError = -3,
	LdrModulesUnloaded = -2,
	LdrModulesUnloading = -1,
	LdrModulesPlaceHolder = 0,
	LdrModulesMapping = 1,
	LdrModulesMapped = 2,
	LdrModulesWaitingForDependencies = 3,
	LdrModulesSnapping = 4,
	LdrModulesSnapped = 5,
	LdrModulesCondensed = 6,
	LdrModulesReadyToInit = 7,
	LdrModulesInitializing = 8,
	LdrModulesReadyToRun = 9
};

enum LDR_DLL_LOAD_REASON
{
	LoadReasonStaticDependency = 0,
	LoadReasonStaticForwarderDependency = 1,
	LoadReasonDynamicForwarderDependency = 2,
	LoadReasonDelayloadDependency = 3,
	LoadReasonDynamicLoad = 4,
	LoadReasonAsImageLoad = 5,
	LoadReasonAsDataLoad = 6,
	LoadReasonEnclavePrimary = 7,
	LoadReasonEnclaveDependency = 8,
	LoadReasonPatchImage = 9,
	LoadReasonUnknown = -1
};

//0x4 bytes (sizeof)
enum LDR_HOT_PATCH_STATE
{
	LdrHotPatchBaseImage = 0,
	LdrHotPatchNotApplied = 1,
	LdrHotPatchAppliedReverse = 2,
	LdrHotPatchAppliedForward = 3,
	LdrHotPatchFailedToPatch = 4,
	LdrHotPatchStateMax = 5
};

typedef struct _PEB_LDR_DATA
{
	ULONG Length;                                                           //0x0
	UCHAR Initialized;                                                      //0x4
	PVOID SsHandle;                                                         //0x8
	LIST_ENTRY InLoadOrderModuleList;                               //0x10
	LIST_ENTRY InMemoryOrderModuleList;                             //0x20
	LIST_ENTRY InInitializationOrderModuleList;                     //0x30
	PVOID EntryInProgress;                                                  //0x40
	UCHAR ShutdownInProgress;                                               //0x48
	PVOID ShutdownThreadId;                                                 //0x50
} PEB_LDR_DATA, * PPEB_LDR_DATA;

//0x8 bytes (sizeof)
typedef struct _LDRP_CSLIST
{
	SINGLE_LIST_ENTRY* Tail;                                        //0x0
} LDRP_CSLIST, * PLDRP_CSLIST;

//0x50 bytes (sizeof)
typedef struct _LDR_DDAG_NODE
{
	LIST_ENTRY Modules;                                             //0x0
	struct _LDR_SERVICE_TAG_RECORD* ServiceTagList;                         //0x10
	ULONG LoadCount;                                                        //0x18
	ULONG LoadWhileUnloadingCount;                                          //0x1c
	ULONG LowestLink;                                                       //0x20
	LDRP_CSLIST Dependencies;                                       //0x28
	LDRP_CSLIST IncomingDependencies;                               //0x30
	LDR_DDAG_STATE State;                                             //0x38
	SINGLE_LIST_ENTRY CondenseLink;                                 //0x40
	ULONG PreorderNumber;                                                   //0x48
} LDR_DDAG_NODE, * PLDR_DDAG_NODE;

//0x28 bytes (sizeof)
typedef struct _RTL_CRITICAL_SECTION
{
	struct _RTL_CRITICAL_SECTION_DEBUG* DebugInfo;                          //0x0
	LONG LockCount;                                                         //0x8
	LONG RecursionCount;                                                    //0xc
	VOID* OwningThread;                                                     //0x10
	VOID* LockSemaphore;                                                    //0x18
	ULONGLONG SpinCount;                                                    //0x20
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;

//0x10 bytes (sizeof)
typedef struct _LEAP_SECOND_DATA
{
	UCHAR Enabled;                                                          //0x0
	ULONG Count;                                                            //0x4
	LARGE_INTEGER Data[1];                                           //0x8
} LEAP_SECOND_DATA, * PLEAP_SECOND_DATA;

//0x118 bytes (sizeof)
typedef struct _LDR_DATA_TABLE_ENTRY_1507
{
	LIST_ENTRY InLoadOrderLinks;                                    //0x0
	LIST_ENTRY InMemoryOrderLinks;                                  //0x10
	LIST_ENTRY InInitializationOrderLinks;                          //0x20
	PVOID DllBase;                                                          //0x30
	PVOID EntryPoint;                                                       //0x38
	ULONG SizeOfImage;                                                      //0x40
	UNICODE_STRING FullDllName;                                     //0x48
	UNICODE_STRING BaseDllName;                                     //0x58
	union
	{
		UCHAR FlagGroup[4];                                                 //0x68
		ULONG Flags;                                                        //0x68
		struct
		{
			ULONG PackagedBinary : 1;                                         //0x68
			ULONG MarkedForRemoval : 1;                                       //0x68
			ULONG ImageDll : 1;                                               //0x68
			ULONG LoadNotificationsSent : 1;                                  //0x68
			ULONG TelemetryEntryProcessed : 1;                                //0x68
			ULONG ProcessStaticImport : 1;                                    //0x68
			ULONG InLegacyLists : 1;                                          //0x68
			ULONG InIndexes : 1;                                              //0x68
			ULONG ShimDll : 1;                                                //0x68
			ULONG InExceptionTable : 1;                                       //0x68
			ULONG ReservedFlags1 : 2;                                         //0x68
			ULONG LoadInProgress : 1;                                         //0x68
			ULONG LoadConfigProcessed : 1;                                    //0x68
			ULONG EntryProcessed : 1;                                         //0x68
			ULONG ProtectDelayLoad : 1;                                       //0x68
			ULONG ReservedFlags3 : 2;                                         //0x68
			ULONG DontCallForThreads : 1;                                     //0x68
			ULONG ProcessAttachCalled : 1;                                    //0x68
			ULONG ProcessAttachFailed : 1;                                    //0x68
			ULONG CorDeferredValidate : 1;                                    //0x68
			ULONG CorImage : 1;                                               //0x68
			ULONG DontRelocate : 1;                                           //0x68
			ULONG CorILOnly : 1;                                              //0x68
			ULONG ReservedFlags5 : 3;                                         //0x68
			ULONG Redirected : 1;                                             //0x68
			ULONG ReservedFlags6 : 2;                                         //0x68
			ULONG CompatDatabaseProcessed : 1;                                //0x68
		};
	};
	USHORT ObsoleteLoadCount;                                               //0x6c
	USHORT TlsIndex;                                                        //0x6e
	LIST_ENTRY HashLinks;                                           //0x70
	ULONG TimeDateStamp;                                                    //0x80
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
	PVOID Lock;                                                             //0x90
	LDR_DDAG_NODE* DdagNode;                                        //0x98
	LIST_ENTRY NodeModuleLink;                                      //0xa0
	struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
	PVOID ParentDllBase;                                                    //0xb8
	PVOID SwitchBackContext;                                                //0xc0
	RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
	RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
	ULONGLONG OriginalBase;                                                 //0xf8
	LARGE_INTEGER LoadTime;                                          //0x100
	ULONG BaseNameHashValue;                                                //0x108
	LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
	ULONG ImplicitPathOptions;                                              //0x110
	ULONG ReferenceCount;                                                   //0x114
} LDR_DATA_TABLE_ENTRY_1507, * PLDR_DATA_TABLE_ENTRY_1507;

//0x120 bytes (sizeof)
typedef struct _LDR_DATA_TABLE_ENTRY_1607
{
	LIST_ENTRY InLoadOrderLinks;                                    //0x0
	LIST_ENTRY InMemoryOrderLinks;                                  //0x10
	LIST_ENTRY InInitializationOrderLinks;                          //0x20
	PVOID DllBase;                                                          //0x30
	PVOID EntryPoint;                                                       //0x38
	ULONG SizeOfImage;                                                      //0x40
	UNICODE_STRING FullDllName;                                     //0x48
	UNICODE_STRING BaseDllName;                                     //0x58
	union
	{
		UCHAR FlagGroup[4];                                                 //0x68
		ULONG Flags;                                                        //0x68
		struct
		{
			ULONG PackagedBinary : 1;                                         //0x68
			ULONG MarkedForRemoval : 1;                                       //0x68
			ULONG ImageDll : 1;                                               //0x68
			ULONG LoadNotificationsSent : 1;                                  //0x68
			ULONG TelemetryEntryProcessed : 1;                                //0x68
			ULONG ProcessStaticImport : 1;                                    //0x68
			ULONG InLegacyLists : 1;                                          //0x68
			ULONG InIndexes : 1;                                              //0x68
			ULONG ShimDll : 1;                                                //0x68
			ULONG InExceptionTable : 1;                                       //0x68
			ULONG ReservedFlags1 : 2;                                         //0x68
			ULONG LoadInProgress : 1;                                         //0x68
			ULONG LoadConfigProcessed : 1;                                    //0x68
			ULONG EntryProcessed : 1;                                         //0x68
			ULONG ProtectDelayLoad : 1;                                       //0x68
			ULONG ReservedFlags3 : 2;                                         //0x68
			ULONG DontCallForThreads : 1;                                     //0x68
			ULONG ProcessAttachCalled : 1;                                    //0x68
			ULONG ProcessAttachFailed : 1;                                    //0x68
			ULONG CorDeferredValidate : 1;                                    //0x68
			ULONG CorImage : 1;                                               //0x68
			ULONG DontRelocate : 1;                                           //0x68
			ULONG CorILOnly : 1;                                              //0x68
			ULONG ReservedFlags5 : 3;                                         //0x68
			ULONG Redirected : 1;                                             //0x68
			ULONG ReservedFlags6 : 2;                                         //0x68
			ULONG CompatDatabaseProcessed : 1;                                //0x68
		};
	};
	USHORT ObsoleteLoadCount;                                               //0x6c
	USHORT TlsIndex;                                                        //0x6e
	LIST_ENTRY HashLinks;                                           //0x70
	ULONG TimeDateStamp;                                                    //0x80
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
	PVOID Lock;                                                             //0x90
	LDR_DDAG_NODE* DdagNode;                                        //0x98
	LIST_ENTRY NodeModuleLink;                                      //0xa0
	struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
	PVOID ParentDllBase;                                                    //0xb8
	PVOID SwitchBackContext;                                                //0xc0
	RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
	RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
	ULONGLONG OriginalBase;                                                 //0xf8
	LARGE_INTEGER LoadTime;                                          //0x100
	ULONG BaseNameHashValue;                                                //0x108
	LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
	ULONG ImplicitPathOptions;                                              //0x110
	ULONG ReferenceCount;                                                   //0x114
	ULONG DependentLoadFlags;                                               //0x118
} LDR_DATA_TABLE_ENTRY_1607, * PLDR_DATA_TABLE_ENTRY_1607;

//0x138 bytes (sizeof)
typedef struct _LDR_DATA_TABLE_ENTRY_WIN11
{
	LIST_ENTRY InLoadOrderLinks;                                    //0x0
	LIST_ENTRY InMemoryOrderLinks;                                  //0x10
	LIST_ENTRY InInitializationOrderLinks;                          //0x20
	PVOID DllBase;                                                          //0x30
	PVOID EntryPoint;                                                       //0x38
	ULONG SizeOfImage;                                                      //0x40
	UNICODE_STRING FullDllName;                                     //0x48
	UNICODE_STRING BaseDllName;                                     //0x58
	union
	{
		UCHAR FlagGroup[4];                                                 //0x68
		ULONG Flags;                                                        //0x68
		struct
		{
			ULONG PackagedBinary : 1;                                         //0x68
			ULONG MarkedForRemoval : 1;                                       //0x68
			ULONG ImageDll : 1;                                               //0x68
			ULONG LoadNotificationsSent : 1;                                  //0x68
			ULONG TelemetryEntryProcessed : 1;                                //0x68
			ULONG ProcessStaticImport : 1;                                    //0x68
			ULONG InLegacyLists : 1;                                          //0x68
			ULONG InIndexes : 1;                                              //0x68
			ULONG ShimDll : 1;                                                //0x68
			ULONG InExceptionTable : 1;                                       //0x68
			ULONG ReservedFlags1 : 2;                                         //0x68
			ULONG LoadInProgress : 1;                                         //0x68
			ULONG LoadConfigProcessed : 1;                                    //0x68
			ULONG EntryProcessed : 1;                                         //0x68
			ULONG ProtectDelayLoad : 1;                                       //0x68
			ULONG ReservedFlags3 : 2;                                         //0x68
			ULONG DontCallForThreads : 1;                                     //0x68
			ULONG ProcessAttachCalled : 1;                                    //0x68
			ULONG ProcessAttachFailed : 1;                                    //0x68
			ULONG CorDeferredValidate : 1;                                    //0x68
			ULONG CorImage : 1;                                               //0x68
			ULONG DontRelocate : 1;                                           //0x68
			ULONG CorILOnly : 1;                                              //0x68
			ULONG ChpeImage : 1;                                              //0x68
			ULONG ChpeEmulatorImage : 1;                                      //0x68
			ULONG ReservedFlags5 : 1;                                         //0x68
			ULONG Redirected : 1;                                             //0x68
			ULONG ReservedFlags6 : 2;                                         //0x68
			ULONG CompatDatabaseProcessed : 1;                                //0x68
		};
	};
	USHORT ObsoleteLoadCount;                                               //0x6c
	USHORT TlsIndex;                                                        //0x6e
	LIST_ENTRY HashLinks;                                           //0x70
	ULONG TimeDateStamp;                                                    //0x80
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
	PVOID Lock;                                                             //0x90
	LDR_DDAG_NODE* DdagNode;                                        //0x98
	LIST_ENTRY NodeModuleLink;                                      //0xa0
	struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
	PVOID ParentDllBase;                                                    //0xb8
	PVOID SwitchBackContext;                                                //0xc0
	RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
	RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
	ULONGLONG OriginalBase;                                                 //0xf8
	LARGE_INTEGER LoadTime;                                          //0x100
	ULONG BaseNameHashValue;                                                //0x108
	LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
	ULONG ImplicitPathOptions;                                              //0x110
	ULONG ReferenceCount;                                                   //0x114
	ULONG DependentLoadFlags;                                               //0x118
	UCHAR SigningLevel;                                                     //0x11c
	ULONG CheckSum;                                                         //0x120
	PVOID ActivePatchImageBase;                                             //0x128
	LDR_HOT_PATCH_STATE HotPatchState;                                //0x130
} LDR_DATA_TABLE_ENTRY_WIN11, * PLDR_DATA_TABLE_ENTRY_WIN11;

//0x18 bytes (sizeof)
typedef struct _CURDIR
{
	UNICODE_STRING DosPath;                                         //0x0
	VOID* Handle;                                                           //0x10
} CURDIR, * PCURDIR;

//0x18 bytes (sizeof)
typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;                                                           //0x0
	USHORT Length;                                                          //0x2
	ULONG TimeStamp;                                                        //0x4
	STRING DosPath;                                                 //0x8
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

//0x410 bytes (sizeof)
typedef struct _RTL_USER_PROCESS_PARAMETERS_1507
{
	ULONG MaximumLength;                                                    //0x0
	ULONG Length;                                                           //0x4
	ULONG Flags;                                                            //0x8
	ULONG DebugFlags;                                                       //0xc
	VOID* ConsoleHandle;                                                    //0x10
	ULONG ConsoleFlags;                                                     //0x18
	VOID* StandardInput;                                                    //0x20
	VOID* StandardOutput;                                                   //0x28
	VOID* StandardError;                                                    //0x30
	CURDIR CurrentDirectory;                                        //0x38
	UNICODE_STRING DllPath;                                         //0x50
	UNICODE_STRING ImagePathName;                                   //0x60
	UNICODE_STRING CommandLine;                                     //0x70
	VOID* Environment;                                                      //0x80
	ULONG StartingX;                                                        //0x88
	ULONG StartingY;                                                        //0x8c
	ULONG CountX;                                                           //0x90
	ULONG CountY;                                                           //0x94
	ULONG CountCharsX;                                                      //0x98
	ULONG CountCharsY;                                                      //0x9c
	ULONG FillAttribute;                                                    //0xa0
	ULONG WindowFlags;                                                      //0xa4
	ULONG ShowWindowFlags;                                                  //0xa8
	UNICODE_STRING WindowTitle;                                     //0xb0
	UNICODE_STRING DesktopInfo;                                     //0xc0
	UNICODE_STRING ShellInfo;                                       //0xd0
	UNICODE_STRING RuntimeData;                                     //0xe0
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];                  //0xf0
	ULONGLONG EnvironmentSize;                                              //0x3f0
	ULONGLONG EnvironmentVersion;                                           //0x3f8
	VOID* PackageDependencyData;                                            //0x400
	ULONG ProcessGroupId;                                                   //0x408
	ULONG LoaderThreads;                                                    //0x40c
} RTL_USER_PROCESS_PARAMETERS_1507, * PRTL_USER_PROCESS_PARAMETERS_1507;

//0x420 bytes (sizeof)
typedef struct _RTL_USER_PROCESS_PARAMETERS_1809
{
	ULONG MaximumLength;                                                    //0x0
	ULONG Length;                                                           //0x4
	ULONG Flags;                                                            //0x8
	ULONG DebugFlags;                                                       //0xc
	VOID* ConsoleHandle;                                                    //0x10
	ULONG ConsoleFlags;                                                     //0x18
	VOID* StandardInput;                                                    //0x20
	VOID* StandardOutput;                                                   //0x28
	VOID* StandardError;                                                    //0x30
	CURDIR CurrentDirectory;                                        //0x38
	UNICODE_STRING DllPath;                                         //0x50
	UNICODE_STRING ImagePathName;                                   //0x60
	UNICODE_STRING CommandLine;                                     //0x70
	VOID* Environment;                                                      //0x80
	ULONG StartingX;                                                        //0x88
	ULONG StartingY;                                                        //0x8c
	ULONG CountX;                                                           //0x90
	ULONG CountY;                                                           //0x94
	ULONG CountCharsX;                                                      //0x98
	ULONG CountCharsY;                                                      //0x9c
	ULONG FillAttribute;                                                    //0xa0
	ULONG WindowFlags;                                                      //0xa4
	ULONG ShowWindowFlags;                                                  //0xa8
	UNICODE_STRING WindowTitle;                                     //0xb0
	UNICODE_STRING DesktopInfo;                                     //0xc0
	UNICODE_STRING ShellInfo;                                       //0xd0
	UNICODE_STRING RuntimeData;                                     //0xe0
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];                  //0xf0
	ULONGLONG EnvironmentSize;                                              //0x3f0
	ULONGLONG EnvironmentVersion;                                           //0x3f8
	VOID* PackageDependencyData;                                            //0x400
	ULONG ProcessGroupId;                                                   //0x408
	ULONG LoaderThreads;                                                    //0x40c
	UNICODE_STRING RedirectionDllName;                              //0x410
} RTL_USER_PROCESS_PARAMETERS_1809, * PRTL_USER_PROCESS_PARAMETERS_1809;

//0x440 bytes (sizeof)
typedef struct _RTL_USER_PROCESS_PARAMETERS_1903
{
	ULONG MaximumLength;                                                    //0x0
	ULONG Length;                                                           //0x4
	ULONG Flags;                                                            //0x8
	ULONG DebugFlags;                                                       //0xc
	VOID* ConsoleHandle;                                                    //0x10
	ULONG ConsoleFlags;                                                     //0x18
	VOID* StandardInput;                                                    //0x20
	VOID* StandardOutput;                                                   //0x28
	VOID* StandardError;                                                    //0x30
	CURDIR CurrentDirectory;                                        //0x38
	UNICODE_STRING DllPath;                                         //0x50
	UNICODE_STRING ImagePathName;                                   //0x60
	UNICODE_STRING CommandLine;                                     //0x70
	VOID* Environment;                                                      //0x80
	ULONG StartingX;                                                        //0x88
	ULONG StartingY;                                                        //0x8c
	ULONG CountX;                                                           //0x90
	ULONG CountY;                                                           //0x94
	ULONG CountCharsX;                                                      //0x98
	ULONG CountCharsY;                                                      //0x9c
	ULONG FillAttribute;                                                    //0xa0
	ULONG WindowFlags;                                                      //0xa4
	ULONG ShowWindowFlags;                                                  //0xa8
	UNICODE_STRING WindowTitle;                                     //0xb0
	UNICODE_STRING DesktopInfo;                                     //0xc0
	UNICODE_STRING ShellInfo;                                       //0xd0
	UNICODE_STRING RuntimeData;                                     //0xe0
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];                  //0xf0
	ULONGLONG EnvironmentSize;                                              //0x3f0
	ULONGLONG EnvironmentVersion;                                           //0x3f8
	VOID* PackageDependencyData;                                            //0x400
	ULONG ProcessGroupId;                                                   //0x408
	ULONG LoaderThreads;                                                    //0x40c
	UNICODE_STRING RedirectionDllName;                              //0x410
	UNICODE_STRING HeapPartitionName;                               //0x420
	ULONGLONG* DefaultThreadpoolCpuSetMasks;                                //0x430
	ULONG DefaultThreadpoolCpuSetMaskCount;                                 //0x438
	ULONG DefaultThreadpoolThreadMaximum;                                   //0x43c
} RTL_USER_PROCESS_PARAMETERS_1903, * PRTL_USER_PROCESS_PARAMETERS_1903;

//0x388 bytes (sizeof)
typedef struct _PEB_1507
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR IsPackagedProcess : 1;                                      //0x3
			UCHAR IsAppContainer : 1;                                         //0x3
			UCHAR IsProtectedProcessLight : 1;                                //0x3
			UCHAR SpareBits : 1;                                              //0x3
		};
	};
	UCHAR Padding0[4];                                                      //0x4
	PVOID Mutant;                                                           //0x8
	PVOID ImageBaseAddress;                                                 //0x10
	PEB_LDR_DATA* Ldr;                                              //0x18
	RTL_USER_PROCESS_PARAMETERS_1507* ProcessParameters;                 //0x20
	PVOID SubSystemData;                                                    //0x28
	PVOID ProcessHeap;                                                      //0x30
	RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
	PVOID AtlThunkSListPtr;                                                 //0x40
	PVOID IFEOKey;                                                          //0x48
	union
	{
		ULONG CrossProcessFlags;                                            //0x50
		struct
		{
			ULONG ProcessInJob : 1;                                           //0x50
			ULONG ProcessInitializing : 1;                                    //0x50
			ULONG ProcessUsingVEH : 1;                                        //0x50
			ULONG ProcessUsingVCH : 1;                                        //0x50
			ULONG ProcessUsingFTH : 1;                                        //0x50
			ULONG ReservedBits0 : 27;                                         //0x50
		};
	};
	UCHAR Padding1[4];                                                      //0x54
	union
	{
		PVOID KernelCallbackTable;                                          //0x58
		PVOID UserSharedInfoPtr;                                            //0x58
	};
	ULONG SystemReserved[1];                                                //0x60
	ULONG AtlThunkSListPtr32;                                               //0x64
	PVOID ApiSetMap;                                                        //0x68
	ULONG TlsExpansionCounter;                                              //0x70
	UCHAR Padding2[4];                                                      //0x74
	PVOID TlsBitmap;                                                        //0x78
	ULONG TlsBitmapBits[2];                                                 //0x80
	PVOID ReadOnlySharedMemoryBase;                                         //0x88
	PVOID SparePvoid0;                                                      //0x90
	VOID** ReadOnlyStaticServerData;                                        //0x98
	PVOID AnsiCodePageData;                                                 //0xa0
	PVOID OemCodePageData;                                                  //0xa8
	PVOID UnicodeCaseTableData;                                             //0xb0
	ULONG NumberOfProcessors;                                               //0xb8
	ULONG NtGlobalFlag;                                                     //0xbc
	LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
	ULONGLONG HeapSegmentReserve;                                           //0xc8
	ULONGLONG HeapSegmentCommit;                                            //0xd0
	ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
	ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
	ULONG NumberOfHeaps;                                                    //0xe8
	ULONG MaximumNumberOfHeaps;                                             //0xec
	VOID** ProcessHeaps;                                                    //0xf0
	PVOID GdiSharedHandleTable;                                             //0xf8
	PVOID ProcessStarterHelper;                                             //0x100
	ULONG GdiDCAttributeList;                                               //0x108
	UCHAR Padding3[4];                                                      //0x10c
	RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
	ULONG OSMajorVersion;                                                   //0x118
	ULONG OSMinorVersion;                                                   //0x11c
	USHORT OSBuildNumber;                                                   //0x120
	USHORT OSCSDVersion;                                                    //0x122
	ULONG OSPlatformId;                                                     //0x124
	ULONG ImageSubsystem;                                                   //0x128
	ULONG ImageSubsystemMajorVersion;                                       //0x12c
	ULONG ImageSubsystemMinorVersion;                                       //0x130
	UCHAR Padding4[4];                                                      //0x134
	ULONGLONG ActiveProcessAffinityMask;                                    //0x138
	ULONG GdiHandleBuffer[60];                                              //0x140
	VOID(*PostProcessInitRoutine)();                                       //0x230
	PVOID TlsExpansionBitmap;                                               //0x238
	ULONG TlsExpansionBitmapBits[32];                                       //0x240
	ULONG SessionId;                                                        //0x2c0
	UCHAR Padding5[4];                                                      //0x2c4
	ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
	ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
	PVOID pShimData;                                                        //0x2d8
	PVOID AppCompatInfo;                                                    //0x2e0
	UNICODE_STRING CSDVersion;                                      //0x2e8
	struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x2f8
	struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x300
	struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x308
	struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x310
	ULONGLONG MinimumStackCommit;                                           //0x318
	struct _FLS_CALLBACK_INFO* FlsCallback;                                 //0x320
	LIST_ENTRY FlsListHead;                                         //0x328
	PVOID FlsBitmap;                                                        //0x338
	ULONG FlsBitmapBits[4];                                                 //0x340
	ULONG FlsHighIndex;                                                     //0x350
	PVOID WerRegistrationData;                                              //0x358
	PVOID WerShipAssertPtr;                                                 //0x360
	PVOID pUnused;                                                          //0x368
	PVOID pImageHeaderHash;                                                 //0x370
	union
	{
		ULONG TracingFlags;                                                 //0x378
		struct
		{
			ULONG HeapTracingEnabled : 1;                                     //0x378
			ULONG CritSecTracingEnabled : 1;                                  //0x378
			ULONG LibLoaderTracingEnabled : 1;                                //0x378
			ULONG SpareTracingBits : 29;                                      //0x378
		};
	};
	UCHAR Padding6[4];                                                      //0x37c
	ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
} PEB_1507, * PPEB_1507;

//0x7a0 bytes (sizeof)
typedef struct _PEB_1511
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR IsPackagedProcess : 1;                                      //0x3
			UCHAR IsAppContainer : 1;                                         //0x3
			UCHAR IsProtectedProcessLight : 1;                                //0x3
			UCHAR SpareBits : 1;                                              //0x3
		};
	};
	UCHAR Padding0[4];                                                      //0x4
	VOID* Mutant;                                                           //0x8
	VOID* ImageBaseAddress;                                                 //0x10
	PEB_LDR_DATA* Ldr;                                              //0x18
	RTL_USER_PROCESS_PARAMETERS_1507* ProcessParameters;                 //0x20
	VOID* SubSystemData;                                                    //0x28
	VOID* ProcessHeap;                                                      //0x30
	RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
	VOID* AtlThunkSListPtr;                                                 //0x40
	VOID* IFEOKey;                                                          //0x48
	union
	{
		ULONG CrossProcessFlags;                                            //0x50
		struct
		{
			ULONG ProcessInJob : 1;                                           //0x50
			ULONG ProcessInitializing : 1;                                    //0x50
			ULONG ProcessUsingVEH : 1;                                        //0x50
			ULONG ProcessUsingVCH : 1;                                        //0x50
			ULONG ProcessUsingFTH : 1;                                        //0x50
			ULONG ReservedBits0 : 27;                                         //0x50
		};
	};
	UCHAR Padding1[4];                                                      //0x54
	union
	{
		VOID* KernelCallbackTable;                                          //0x58
		VOID* UserSharedInfoPtr;                                            //0x58
	};
	ULONG SystemReserved[1];                                                //0x60
	ULONG AtlThunkSListPtr32;                                               //0x64
	VOID* ApiSetMap;                                                        //0x68
	ULONG TlsExpansionCounter;                                              //0x70
	UCHAR Padding2[4];                                                      //0x74
	VOID* TlsBitmap;                                                        //0x78
	ULONG TlsBitmapBits[2];                                                 //0x80
	VOID* ReadOnlySharedMemoryBase;                                         //0x88
	VOID* SparePvoid0;                                                      //0x90
	VOID** ReadOnlyStaticServerData;                                        //0x98
	VOID* AnsiCodePageData;                                                 //0xa0
	VOID* OemCodePageData;                                                  //0xa8
	VOID* UnicodeCaseTableData;                                             //0xb0
	ULONG NumberOfProcessors;                                               //0xb8
	ULONG NtGlobalFlag;                                                     //0xbc
	LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
	ULONGLONG HeapSegmentReserve;                                           //0xc8
	ULONGLONG HeapSegmentCommit;                                            //0xd0
	ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
	ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
	ULONG NumberOfHeaps;                                                    //0xe8
	ULONG MaximumNumberOfHeaps;                                             //0xec
	VOID** ProcessHeaps;                                                    //0xf0
	VOID* GdiSharedHandleTable;                                             //0xf8
	VOID* ProcessStarterHelper;                                             //0x100
	ULONG GdiDCAttributeList;                                               //0x108
	UCHAR Padding3[4];                                                      //0x10c
	RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
	ULONG OSMajorVersion;                                                   //0x118
	ULONG OSMinorVersion;                                                   //0x11c
	USHORT OSBuildNumber;                                                   //0x120
	USHORT OSCSDVersion;                                                    //0x122
	ULONG OSPlatformId;                                                     //0x124
	ULONG ImageSubsystem;                                                   //0x128
	ULONG ImageSubsystemMajorVersion;                                       //0x12c
	ULONG ImageSubsystemMinorVersion;                                       //0x130
	UCHAR Padding4[4];                                                      //0x134
	ULONGLONG ActiveProcessAffinityMask;                                    //0x138
	ULONG GdiHandleBuffer[60];                                              //0x140
	VOID(*PostProcessInitRoutine)();                                       //0x230
	VOID* TlsExpansionBitmap;                                               //0x238
	ULONG TlsExpansionBitmapBits[32];                                       //0x240
	ULONG SessionId;                                                        //0x2c0
	UCHAR Padding5[4];                                                      //0x2c4
	ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
	ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
	VOID* pShimData;                                                        //0x2d8
	VOID* AppCompatInfo;                                                    //0x2e0
	UNICODE_STRING CSDVersion;                                      //0x2e8
	struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x2f8
	struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x300
	struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x308
	struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x310
	ULONGLONG MinimumStackCommit;                                           //0x318
	struct _FLS_CALLBACK_INFO* FlsCallback;                                 //0x320
	LIST_ENTRY FlsListHead;                                         //0x328
	VOID* FlsBitmap;                                                        //0x338
	ULONG FlsBitmapBits[4];                                                 //0x340
	ULONG FlsHighIndex;                                                     //0x350
	VOID* WerRegistrationData;                                              //0x358
	VOID* WerShipAssertPtr;                                                 //0x360
	VOID* pUnused;                                                          //0x368
	VOID* pImageHeaderHash;                                                 //0x370
	union
	{
		ULONG TracingFlags;                                                 //0x378
		struct
		{
			ULONG HeapTracingEnabled : 1;                                     //0x378
			ULONG CritSecTracingEnabled : 1;                                  //0x378
			ULONG LibLoaderTracingEnabled : 1;                                //0x378
			ULONG SpareTracingBits : 29;                                      //0x378
		};
	};
	UCHAR Padding6[4];                                                      //0x37c
	ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
	ULONGLONG TppWorkerpListLock;                                           //0x388
	LIST_ENTRY TppWorkerpList;                                      //0x390
	VOID* WaitOnAddressHashTable[128];                                      //0x3a0
} PEB_1511, * PPEB_1511;

//0x7b0 bytes (sizeof)
typedef struct _PEB_1709
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR IsPackagedProcess : 1;                                      //0x3
			UCHAR IsAppContainer : 1;                                         //0x3
			UCHAR IsProtectedProcessLight : 1;                                //0x3
			UCHAR IsLongPathAwareProcess : 1;                                 //0x3
		};
	};
	UCHAR Padding0[4];                                                      //0x4
	VOID* Mutant;                                                           //0x8
	VOID* ImageBaseAddress;                                                 //0x10
	PEB_LDR_DATA* Ldr;                                              //0x18
	RTL_USER_PROCESS_PARAMETERS_1507* ProcessParameters;                 //0x20
	VOID* SubSystemData;                                                    //0x28
	VOID* ProcessHeap;                                                      //0x30
	RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
	SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x40
	VOID* IFEOKey;                                                          //0x48
	union
	{
		ULONG CrossProcessFlags;                                            //0x50
		struct
		{
			ULONG ProcessInJob : 1;                                           //0x50
			ULONG ProcessInitializing : 1;                                    //0x50
			ULONG ProcessUsingVEH : 1;                                        //0x50
			ULONG ProcessUsingVCH : 1;                                        //0x50
			ULONG ProcessUsingFTH : 1;                                        //0x50
			ULONG ProcessPreviouslyThrottled : 1;                             //0x50
			ULONG ProcessCurrentlyThrottled : 1;                              //0x50
			ULONG ReservedBits0 : 25;                                         //0x50
		};
	};
	UCHAR Padding1[4];                                                      //0x54
	union
	{
		VOID* KernelCallbackTable;                                          //0x58
		VOID* UserSharedInfoPtr;                                            //0x58
	};
	ULONG SystemReserved;                                                   //0x60
	ULONG AtlThunkSListPtr32;                                               //0x64
	VOID* ApiSetMap;                                                        //0x68
	ULONG TlsExpansionCounter;                                              //0x70
	UCHAR Padding2[4];                                                      //0x74
	VOID* TlsBitmap;                                                        //0x78
	ULONG TlsBitmapBits[2];                                                 //0x80
	VOID* ReadOnlySharedMemoryBase;                                         //0x88
	VOID* SharedData;                                                       //0x90
	VOID** ReadOnlyStaticServerData;                                        //0x98
	VOID* AnsiCodePageData;                                                 //0xa0
	VOID* OemCodePageData;                                                  //0xa8
	VOID* UnicodeCaseTableData;                                             //0xb0
	ULONG NumberOfProcessors;                                               //0xb8
	ULONG NtGlobalFlag;                                                     //0xbc
	LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
	ULONGLONG HeapSegmentReserve;                                           //0xc8
	ULONGLONG HeapSegmentCommit;                                            //0xd0
	ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
	ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
	ULONG NumberOfHeaps;                                                    //0xe8
	ULONG MaximumNumberOfHeaps;                                             //0xec
	VOID** ProcessHeaps;                                                    //0xf0
	VOID* GdiSharedHandleTable;                                             //0xf8
	VOID* ProcessStarterHelper;                                             //0x100
	ULONG GdiDCAttributeList;                                               //0x108
	UCHAR Padding3[4];                                                      //0x10c
	RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
	ULONG OSMajorVersion;                                                   //0x118
	ULONG OSMinorVersion;                                                   //0x11c
	USHORT OSBuildNumber;                                                   //0x120
	USHORT OSCSDVersion;                                                    //0x122
	ULONG OSPlatformId;                                                     //0x124
	ULONG ImageSubsystem;                                                   //0x128
	ULONG ImageSubsystemMajorVersion;                                       //0x12c
	ULONG ImageSubsystemMinorVersion;                                       //0x130
	UCHAR Padding4[4];                                                      //0x134
	ULONGLONG ActiveProcessAffinityMask;                                    //0x138
	ULONG GdiHandleBuffer[60];                                              //0x140
	VOID(*PostProcessInitRoutine)();                                       //0x230
	VOID* TlsExpansionBitmap;                                               //0x238
	ULONG TlsExpansionBitmapBits[32];                                       //0x240
	ULONG SessionId;                                                        //0x2c0
	UCHAR Padding5[4];                                                      //0x2c4
	ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
	ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
	VOID* pShimData;                                                        //0x2d8
	VOID* AppCompatInfo;                                                    //0x2e0
	UNICODE_STRING CSDVersion;                                      //0x2e8
	struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x2f8
	struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x300
	struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x308
	struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x310
	ULONGLONG MinimumStackCommit;                                           //0x318
	struct _FLS_CALLBACK_INFO* FlsCallback;                                 //0x320
	LIST_ENTRY FlsListHead;                                         //0x328
	VOID* FlsBitmap;                                                        //0x338
	ULONG FlsBitmapBits[4];                                                 //0x340
	ULONG FlsHighIndex;                                                     //0x350
	VOID* WerRegistrationData;                                              //0x358
	VOID* WerShipAssertPtr;                                                 //0x360
	VOID* pUnused;                                                          //0x368
	VOID* pImageHeaderHash;                                                 //0x370
	union
	{
		ULONG TracingFlags;                                                 //0x378
		struct
		{
			ULONG HeapTracingEnabled : 1;                                     //0x378
			ULONG CritSecTracingEnabled : 1;                                  //0x378
			ULONG LibLoaderTracingEnabled : 1;                                //0x378
			ULONG SpareTracingBits : 29;                                      //0x378
		};
	};
	UCHAR Padding6[4];                                                      //0x37c
	ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
	ULONGLONG TppWorkerpListLock;                                           //0x388
	LIST_ENTRY TppWorkerpList;                                      //0x390
	VOID* WaitOnAddressHashTable[128];                                      //0x3a0
	VOID* TelemetryCoverageHeader;                                          //0x7a0
	ULONG CloudFileFlags;                                                   //0x7a8
} PEB_1709, * PPEB_1709;

//0x7b8 bytes (sizeof)
typedef struct _PEB_1803
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR IsPackagedProcess : 1;                                      //0x3
			UCHAR IsAppContainer : 1;                                         //0x3
			UCHAR IsProtectedProcessLight : 1;                                //0x3
			UCHAR IsLongPathAwareProcess : 1;                                 //0x3
		};
	};
	UCHAR Padding0[4];                                                      //0x4
	VOID* Mutant;                                                           //0x8
	VOID* ImageBaseAddress;                                                 //0x10
	PEB_LDR_DATA* Ldr;                                              //0x18
	RTL_USER_PROCESS_PARAMETERS_1507* ProcessParameters;                 //0x20
	VOID* SubSystemData;                                                    //0x28
	VOID* ProcessHeap;                                                      //0x30
	RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
	SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x40
	VOID* IFEOKey;                                                          //0x48
	union
	{
		ULONG CrossProcessFlags;                                            //0x50
		struct
		{
			ULONG ProcessInJob : 1;                                           //0x50
			ULONG ProcessInitializing : 1;                                    //0x50
			ULONG ProcessUsingVEH : 1;                                        //0x50
			ULONG ProcessUsingVCH : 1;                                        //0x50
			ULONG ProcessUsingFTH : 1;                                        //0x50
			ULONG ProcessPreviouslyThrottled : 1;                             //0x50
			ULONG ProcessCurrentlyThrottled : 1;                              //0x50
			ULONG ReservedBits0 : 25;                                         //0x50
		};
	};
	UCHAR Padding1[4];                                                      //0x54
	union
	{
		VOID* KernelCallbackTable;                                          //0x58
		VOID* UserSharedInfoPtr;                                            //0x58
	};
	ULONG SystemReserved;                                                   //0x60
	ULONG AtlThunkSListPtr32;                                               //0x64
	VOID* ApiSetMap;                                                        //0x68
	ULONG TlsExpansionCounter;                                              //0x70
	UCHAR Padding2[4];                                                      //0x74
	VOID* TlsBitmap;                                                        //0x78
	ULONG TlsBitmapBits[2];                                                 //0x80
	VOID* ReadOnlySharedMemoryBase;                                         //0x88
	VOID* SharedData;                                                       //0x90
	VOID** ReadOnlyStaticServerData;                                        //0x98
	VOID* AnsiCodePageData;                                                 //0xa0
	VOID* OemCodePageData;                                                  //0xa8
	VOID* UnicodeCaseTableData;                                             //0xb0
	ULONG NumberOfProcessors;                                               //0xb8
	ULONG NtGlobalFlag;                                                     //0xbc
	LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
	ULONGLONG HeapSegmentReserve;                                           //0xc8
	ULONGLONG HeapSegmentCommit;                                            //0xd0
	ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
	ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
	ULONG NumberOfHeaps;                                                    //0xe8
	ULONG MaximumNumberOfHeaps;                                             //0xec
	VOID** ProcessHeaps;                                                    //0xf0
	VOID* GdiSharedHandleTable;                                             //0xf8
	VOID* ProcessStarterHelper;                                             //0x100
	ULONG GdiDCAttributeList;                                               //0x108
	UCHAR Padding3[4];                                                      //0x10c
	RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
	ULONG OSMajorVersion;                                                   //0x118
	ULONG OSMinorVersion;                                                   //0x11c
	USHORT OSBuildNumber;                                                   //0x120
	USHORT OSCSDVersion;                                                    //0x122
	ULONG OSPlatformId;                                                     //0x124
	ULONG ImageSubsystem;                                                   //0x128
	ULONG ImageSubsystemMajorVersion;                                       //0x12c
	ULONG ImageSubsystemMinorVersion;                                       //0x130
	UCHAR Padding4[4];                                                      //0x134
	ULONGLONG ActiveProcessAffinityMask;                                    //0x138
	ULONG GdiHandleBuffer[60];                                              //0x140
	VOID(*PostProcessInitRoutine)();                                       //0x230
	VOID* TlsExpansionBitmap;                                               //0x238
	ULONG TlsExpansionBitmapBits[32];                                       //0x240
	ULONG SessionId;                                                        //0x2c0
	UCHAR Padding5[4];                                                      //0x2c4
	ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
	ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
	VOID* pShimData;                                                        //0x2d8
	VOID* AppCompatInfo;                                                    //0x2e0
	UNICODE_STRING CSDVersion;                                      //0x2e8
	struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x2f8
	struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x300
	struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x308
	struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x310
	ULONGLONG MinimumStackCommit;                                           //0x318
	struct _FLS_CALLBACK_INFO* FlsCallback;                                 //0x320
	LIST_ENTRY FlsListHead;                                         //0x328
	VOID* FlsBitmap;                                                        //0x338
	ULONG FlsBitmapBits[4];                                                 //0x340
	ULONG FlsHighIndex;                                                     //0x350
	VOID* WerRegistrationData;                                              //0x358
	VOID* WerShipAssertPtr;                                                 //0x360
	VOID* pUnused;                                                          //0x368
	VOID* pImageHeaderHash;                                                 //0x370
	union
	{
		ULONG TracingFlags;                                                 //0x378
		struct
		{
			ULONG HeapTracingEnabled : 1;                                     //0x378
			ULONG CritSecTracingEnabled : 1;                                  //0x378
			ULONG LibLoaderTracingEnabled : 1;                                //0x378
			ULONG SpareTracingBits : 29;                                      //0x378
		};
	};
	UCHAR Padding6[4];                                                      //0x37c
	ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
	ULONGLONG TppWorkerpListLock;                                           //0x388
	LIST_ENTRY TppWorkerpList;                                      //0x390
	VOID* WaitOnAddressHashTable[128];                                      //0x3a0
	VOID* TelemetryCoverageHeader;                                          //0x7a0
	ULONG CloudFileFlags;                                                   //0x7a8
	ULONG CloudFileDiagFlags;                                               //0x7ac
	CHAR PlaceholderCompatibilityMode;                                      //0x7b0
	CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
} PEB_1803, * PPEB_1803;

//0x7c8 bytes (sizeof)
typedef struct _PEB_1809
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR IsPackagedProcess : 1;                                      //0x3
			UCHAR IsAppContainer : 1;                                         //0x3
			UCHAR IsProtectedProcessLight : 1;                                //0x3
			UCHAR IsLongPathAwareProcess : 1;                                 //0x3
		};
	};
	UCHAR Padding0[4];                                                      //0x4
	VOID* Mutant;                                                           //0x8
	VOID* ImageBaseAddress;                                                 //0x10
	PEB_LDR_DATA* Ldr;                                              //0x18
	RTL_USER_PROCESS_PARAMETERS_1809* ProcessParameters;                 //0x20
	VOID* SubSystemData;                                                    //0x28
	VOID* ProcessHeap;                                                      //0x30
	RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
	SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x40
	VOID* IFEOKey;                                                          //0x48
	union
	{
		ULONG CrossProcessFlags;                                            //0x50
		struct
		{
			ULONG ProcessInJob : 1;                                           //0x50
			ULONG ProcessInitializing : 1;                                    //0x50
			ULONG ProcessUsingVEH : 1;                                        //0x50
			ULONG ProcessUsingVCH : 1;                                        //0x50
			ULONG ProcessUsingFTH : 1;                                        //0x50
			ULONG ProcessPreviouslyThrottled : 1;                             //0x50
			ULONG ProcessCurrentlyThrottled : 1;                              //0x50
			ULONG ProcessImagesHotPatched : 1;                                //0x50
			ULONG ReservedBits0 : 24;                                         //0x50
		};
	};
	UCHAR Padding1[4];                                                      //0x54
	union
	{
		VOID* KernelCallbackTable;                                          //0x58
		VOID* UserSharedInfoPtr;                                            //0x58
	};
	ULONG SystemReserved;                                                   //0x60
	ULONG AtlThunkSListPtr32;                                               //0x64
	VOID* ApiSetMap;                                                        //0x68
	ULONG TlsExpansionCounter;                                              //0x70
	UCHAR Padding2[4];                                                      //0x74
	VOID* TlsBitmap;                                                        //0x78
	ULONG TlsBitmapBits[2];                                                 //0x80
	VOID* ReadOnlySharedMemoryBase;                                         //0x88
	VOID* SharedData;                                                       //0x90
	VOID** ReadOnlyStaticServerData;                                        //0x98
	VOID* AnsiCodePageData;                                                 //0xa0
	VOID* OemCodePageData;                                                  //0xa8
	VOID* UnicodeCaseTableData;                                             //0xb0
	ULONG NumberOfProcessors;                                               //0xb8
	ULONG NtGlobalFlag;                                                     //0xbc
	LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
	ULONGLONG HeapSegmentReserve;                                           //0xc8
	ULONGLONG HeapSegmentCommit;                                            //0xd0
	ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
	ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
	ULONG NumberOfHeaps;                                                    //0xe8
	ULONG MaximumNumberOfHeaps;                                             //0xec
	VOID** ProcessHeaps;                                                    //0xf0
	VOID* GdiSharedHandleTable;                                             //0xf8
	VOID* ProcessStarterHelper;                                             //0x100
	ULONG GdiDCAttributeList;                                               //0x108
	UCHAR Padding3[4];                                                      //0x10c
	RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
	ULONG OSMajorVersion;                                                   //0x118
	ULONG OSMinorVersion;                                                   //0x11c
	USHORT OSBuildNumber;                                                   //0x120
	USHORT OSCSDVersion;                                                    //0x122
	ULONG OSPlatformId;                                                     //0x124
	ULONG ImageSubsystem;                                                   //0x128
	ULONG ImageSubsystemMajorVersion;                                       //0x12c
	ULONG ImageSubsystemMinorVersion;                                       //0x130
	UCHAR Padding4[4];                                                      //0x134
	ULONGLONG ActiveProcessAffinityMask;                                    //0x138
	ULONG GdiHandleBuffer[60];                                              //0x140
	VOID(*PostProcessInitRoutine)();                                       //0x230
	VOID* TlsExpansionBitmap;                                               //0x238
	ULONG TlsExpansionBitmapBits[32];                                       //0x240
	ULONG SessionId;                                                        //0x2c0
	UCHAR Padding5[4];                                                      //0x2c4
	ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
	ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
	VOID* pShimData;                                                        //0x2d8
	VOID* AppCompatInfo;                                                    //0x2e0
	UNICODE_STRING CSDVersion;                                      //0x2e8
	struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x2f8
	struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x300
	struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x308
	struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x310
	ULONGLONG MinimumStackCommit;                                           //0x318
	struct _FLS_CALLBACK_INFO* FlsCallback;                                 //0x320
	LIST_ENTRY FlsListHead;                                         //0x328
	VOID* FlsBitmap;                                                        //0x338
	ULONG FlsBitmapBits[4];                                                 //0x340
	ULONG FlsHighIndex;                                                     //0x350
	VOID* WerRegistrationData;                                              //0x358
	VOID* WerShipAssertPtr;                                                 //0x360
	VOID* pUnused;                                                          //0x368
	VOID* pImageHeaderHash;                                                 //0x370
	union
	{
		ULONG TracingFlags;                                                 //0x378
		struct
		{
			ULONG HeapTracingEnabled : 1;                                     //0x378
			ULONG CritSecTracingEnabled : 1;                                  //0x378
			ULONG LibLoaderTracingEnabled : 1;                                //0x378
			ULONG SpareTracingBits : 29;                                      //0x378
		};
	};
	UCHAR Padding6[4];                                                      //0x37c
	ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
	ULONGLONG TppWorkerpListLock;                                           //0x388
	LIST_ENTRY TppWorkerpList;                                      //0x390
	VOID* WaitOnAddressHashTable[128];                                      //0x3a0
	VOID* TelemetryCoverageHeader;                                          //0x7a0
	ULONG CloudFileFlags;                                                   //0x7a8
	ULONG CloudFileDiagFlags;                                               //0x7ac
	CHAR PlaceholderCompatibilityMode;                                      //0x7b0
	CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
	LEAP_SECOND_DATA* LeapSecondData;                               //0x7b8
	union
	{
		ULONG LeapSecondFlags;                                              //0x7c0
		struct
		{
			ULONG SixtySecondEnabled : 1;                                     //0x7c0
			ULONG Reserved : 31;                                              //0x7c0
		};
	};
	ULONG NtGlobalFlag2;                                                    //0x7c4
} PEB_1809, * PPEB_1809;

//0x7c8 bytes (sizeof)
typedef struct _PEB_1903
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR IsPackagedProcess : 1;                                      //0x3
			UCHAR IsAppContainer : 1;                                         //0x3
			UCHAR IsProtectedProcessLight : 1;                                //0x3
			UCHAR IsLongPathAwareProcess : 1;                                 //0x3
		};
	};
	UCHAR Padding0[4];                                                      //0x4
	VOID* Mutant;                                                           //0x8
	VOID* ImageBaseAddress;                                                 //0x10
	PEB_LDR_DATA* Ldr;                                              //0x18
	RTL_USER_PROCESS_PARAMETERS_1903* ProcessParameters;                 //0x20
	VOID* SubSystemData;                                                    //0x28
	VOID* ProcessHeap;                                                      //0x30
	RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
	SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x40
	VOID* IFEOKey;                                                          //0x48
	union
	{
		ULONG CrossProcessFlags;                                            //0x50
		struct
		{
			ULONG ProcessInJob : 1;                                           //0x50
			ULONG ProcessInitializing : 1;                                    //0x50
			ULONG ProcessUsingVEH : 1;                                        //0x50
			ULONG ProcessUsingVCH : 1;                                        //0x50
			ULONG ProcessUsingFTH : 1;                                        //0x50
			ULONG ProcessPreviouslyThrottled : 1;                             //0x50
			ULONG ProcessCurrentlyThrottled : 1;                              //0x50
			ULONG ProcessImagesHotPatched : 1;                                //0x50
			ULONG ReservedBits0 : 24;                                         //0x50
		};
	};
	UCHAR Padding1[4];                                                      //0x54
	union
	{
		VOID* KernelCallbackTable;                                          //0x58
		VOID* UserSharedInfoPtr;                                            //0x58
	};
	ULONG SystemReserved;                                                   //0x60
	ULONG AtlThunkSListPtr32;                                               //0x64
	VOID* ApiSetMap;                                                        //0x68
	ULONG TlsExpansionCounter;                                              //0x70
	UCHAR Padding2[4];                                                      //0x74
	VOID* TlsBitmap;                                                        //0x78
	ULONG TlsBitmapBits[2];                                                 //0x80
	VOID* ReadOnlySharedMemoryBase;                                         //0x88
	VOID* SharedData;                                                       //0x90
	VOID** ReadOnlyStaticServerData;                                        //0x98
	VOID* AnsiCodePageData;                                                 //0xa0
	VOID* OemCodePageData;                                                  //0xa8
	VOID* UnicodeCaseTableData;                                             //0xb0
	ULONG NumberOfProcessors;                                               //0xb8
	ULONG NtGlobalFlag;                                                     //0xbc
	LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
	ULONGLONG HeapSegmentReserve;                                           //0xc8
	ULONGLONG HeapSegmentCommit;                                            //0xd0
	ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
	ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
	ULONG NumberOfHeaps;                                                    //0xe8
	ULONG MaximumNumberOfHeaps;                                             //0xec
	VOID** ProcessHeaps;                                                    //0xf0
	VOID* GdiSharedHandleTable;                                             //0xf8
	VOID* ProcessStarterHelper;                                             //0x100
	ULONG GdiDCAttributeList;                                               //0x108
	UCHAR Padding3[4];                                                      //0x10c
	RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
	ULONG OSMajorVersion;                                                   //0x118
	ULONG OSMinorVersion;                                                   //0x11c
	USHORT OSBuildNumber;                                                   //0x120
	USHORT OSCSDVersion;                                                    //0x122
	ULONG OSPlatformId;                                                     //0x124
	ULONG ImageSubsystem;                                                   //0x128
	ULONG ImageSubsystemMajorVersion;                                       //0x12c
	ULONG ImageSubsystemMinorVersion;                                       //0x130
	UCHAR Padding4[4];                                                      //0x134
	ULONGLONG ActiveProcessAffinityMask;                                    //0x138
	ULONG GdiHandleBuffer[60];                                              //0x140
	VOID(*PostProcessInitRoutine)();                                       //0x230
	VOID* TlsExpansionBitmap;                                               //0x238
	ULONG TlsExpansionBitmapBits[32];                                       //0x240
	ULONG SessionId;                                                        //0x2c0
	UCHAR Padding5[4];                                                      //0x2c4
	ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
	ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
	VOID* pShimData;                                                        //0x2d8
	VOID* AppCompatInfo;                                                    //0x2e0
	UNICODE_STRING CSDVersion;                                      //0x2e8
	struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x2f8
	struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x300
	struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x308
	struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x310
	ULONGLONG MinimumStackCommit;                                           //0x318
	struct _FLS_CALLBACK_INFO* FlsCallback;                                 //0x320
	LIST_ENTRY FlsListHead;                                         //0x328
	VOID* FlsBitmap;                                                        //0x338
	ULONG FlsBitmapBits[4];                                                 //0x340
	ULONG FlsHighIndex;                                                     //0x350
	VOID* WerRegistrationData;                                              //0x358
	VOID* WerShipAssertPtr;                                                 //0x360
	VOID* pUnused;                                                          //0x368
	VOID* pImageHeaderHash;                                                 //0x370
	union
	{
		ULONG TracingFlags;                                                 //0x378
		struct
		{
			ULONG HeapTracingEnabled : 1;                                     //0x378
			ULONG CritSecTracingEnabled : 1;                                  //0x378
			ULONG LibLoaderTracingEnabled : 1;                                //0x378
			ULONG SpareTracingBits : 29;                                      //0x378
		};
	};
	UCHAR Padding6[4];                                                      //0x37c
	ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
	ULONGLONG TppWorkerpListLock;                                           //0x388
	LIST_ENTRY TppWorkerpList;                                      //0x390
	VOID* WaitOnAddressHashTable[128];                                      //0x3a0
	VOID* TelemetryCoverageHeader;                                          //0x7a0
	ULONG CloudFileFlags;                                                   //0x7a8
	ULONG CloudFileDiagFlags;                                               //0x7ac
	CHAR PlaceholderCompatibilityMode;                                      //0x7b0
	CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
	LEAP_SECOND_DATA* LeapSecondData;                               //0x7b8
	union
	{
		ULONG LeapSecondFlags;                                              //0x7c0
		struct
		{
			ULONG SixtySecondEnabled : 1;                                     //0x7c0
			ULONG Reserved : 31;                                              //0x7c0
		};
	};
	ULONG NtGlobalFlag2;                                                    //0x7c4
} PEB_1903, * PPEB_1903;

//0x7d0 bytes (sizeof)
typedef struct _PEB_WIN11
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR IsPackagedProcess : 1;                                      //0x3
			UCHAR IsAppContainer : 1;                                         //0x3
			UCHAR IsProtectedProcessLight : 1;                                //0x3
			UCHAR IsLongPathAwareProcess : 1;                                 //0x3
		};
	};
	UCHAR Padding0[4];                                                      //0x4
	VOID* Mutant;                                                           //0x8
	VOID* ImageBaseAddress;                                                 //0x10
	PEB_LDR_DATA* Ldr;                                              //0x18
	RTL_USER_PROCESS_PARAMETERS_1903* ProcessParameters;                 //0x20
	VOID* SubSystemData;                                                    //0x28
	VOID* ProcessHeap;                                                      //0x30
	RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
	SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x40
	VOID* IFEOKey;                                                          //0x48
	union
	{
		ULONG CrossProcessFlags;                                            //0x50
		struct
		{
			ULONG ProcessInJob : 1;                                           //0x50
			ULONG ProcessInitializing : 1;                                    //0x50
			ULONG ProcessUsingVEH : 1;                                        //0x50
			ULONG ProcessUsingVCH : 1;                                        //0x50
			ULONG ProcessUsingFTH : 1;                                        //0x50
			ULONG ProcessPreviouslyThrottled : 1;                             //0x50
			ULONG ProcessCurrentlyThrottled : 1;                              //0x50
			ULONG ProcessImagesHotPatched : 1;                                //0x50
			ULONG ReservedBits0 : 24;                                         //0x50
		};
	};
	UCHAR Padding1[4];                                                      //0x54
	union
	{
		VOID* KernelCallbackTable;                                          //0x58
		VOID* UserSharedInfoPtr;                                            //0x58
	};
	ULONG SystemReserved;                                                   //0x60
	ULONG AtlThunkSListPtr32;                                               //0x64
	VOID* ApiSetMap;                                                        //0x68
	ULONG TlsExpansionCounter;                                              //0x70
	UCHAR Padding2[4];                                                      //0x74
	RTL_BITMAP* TlsBitmap;                                          //0x78
	ULONG TlsBitmapBits[2];                                                 //0x80
	VOID* ReadOnlySharedMemoryBase;                                         //0x88
	VOID* SharedData;                                                       //0x90
	VOID** ReadOnlyStaticServerData;                                        //0x98
	VOID* AnsiCodePageData;                                                 //0xa0
	VOID* OemCodePageData;                                                  //0xa8
	VOID* UnicodeCaseTableData;                                             //0xb0
	ULONG NumberOfProcessors;                                               //0xb8
	ULONG NtGlobalFlag;                                                     //0xbc
	LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
	ULONGLONG HeapSegmentReserve;                                           //0xc8
	ULONGLONG HeapSegmentCommit;                                            //0xd0
	ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
	ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
	ULONG NumberOfHeaps;                                                    //0xe8
	ULONG MaximumNumberOfHeaps;                                             //0xec
	VOID** ProcessHeaps;                                                    //0xf0
	VOID* GdiSharedHandleTable;                                             //0xf8
	VOID* ProcessStarterHelper;                                             //0x100
	ULONG GdiDCAttributeList;                                               //0x108
	UCHAR Padding3[4];                                                      //0x10c
	RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
	ULONG OSMajorVersion;                                                   //0x118
	ULONG OSMinorVersion;                                                   //0x11c
	USHORT OSBuildNumber;                                                   //0x120
	USHORT OSCSDVersion;                                                    //0x122
	ULONG OSPlatformId;                                                     //0x124
	ULONG ImageSubsystem;                                                   //0x128
	ULONG ImageSubsystemMajorVersion;                                       //0x12c
	ULONG ImageSubsystemMinorVersion;                                       //0x130
	UCHAR Padding4[4];                                                      //0x134
	ULONGLONG ActiveProcessAffinityMask;                                    //0x138
	ULONG GdiHandleBuffer[60];                                              //0x140
	VOID(*PostProcessInitRoutine)();                                       //0x230
	RTL_BITMAP* TlsExpansionBitmap;                                 //0x238
	ULONG TlsExpansionBitmapBits[32];                                       //0x240
	ULONG SessionId;                                                        //0x2c0
	UCHAR Padding5[4];                                                      //0x2c4
	ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
	ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
	VOID* pShimData;                                                        //0x2d8
	VOID* AppCompatInfo;                                                    //0x2e0
	UNICODE_STRING CSDVersion;                                      //0x2e8
	struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x2f8
	struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x300
	struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x308
	struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x310
	ULONGLONG MinimumStackCommit;                                           //0x318
	VOID* SparePointers[2];                                                 //0x320
	VOID* PatchLoaderData;                                                  //0x330
	struct _CHPEV2_PROCESS_INFO* ChpeV2ProcessInfo;                         //0x338
	ULONG SpareUlongs[3];                                                   //0x340
	USHORT ActiveCodePage;                                                  //0x34c
	USHORT OemCodePage;                                                     //0x34e
	USHORT UseCaseMapping;                                                  //0x350
	USHORT UnusedNlsField;                                                  //0x352
	VOID* WerRegistrationData;                                              //0x358
	VOID* WerShipAssertPtr;                                                 //0x360
	VOID* EcCodeBitMap;                                                     //0x368
	VOID* pImageHeaderHash;                                                 //0x370
	union
	{
		ULONG TracingFlags;                                                 //0x378
		struct
		{
			ULONG HeapTracingEnabled : 1;                                     //0x378
			ULONG CritSecTracingEnabled : 1;                                  //0x378
			ULONG LibLoaderTracingEnabled : 1;                                //0x378
			ULONG SpareTracingBits : 29;                                      //0x378
		};
	};
	UCHAR Padding6[4];                                                      //0x37c
	ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
	ULONGLONG TppWorkerpListLock;                                           //0x388
	LIST_ENTRY TppWorkerpList;                                      //0x390
	VOID* WaitOnAddressHashTable[128];                                      //0x3a0
	VOID* TelemetryCoverageHeader;                                          //0x7a0
	ULONG CloudFileFlags;                                                   //0x7a8
	ULONG CloudFileDiagFlags;                                               //0x7ac
	CHAR PlaceholderCompatibilityMode;                                      //0x7b0
	CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
	LEAP_SECOND_DATA* LeapSecondData;                               //0x7b8
	union
	{
		ULONG LeapSecondFlags;                                              //0x7c0
		struct
		{
			ULONG SixtySecondEnabled : 1;                                     //0x7c0
			ULONG Reserved : 31;                                              //0x7c0
		};
	};
	ULONG NtGlobalFlag2;                                                    //0x7c4
	ULONGLONG ExtendedFeatureDisableMask;                                   //0x7c8
} PEB_WIN11, * PPEB_WIN11;

// Undocumented.
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

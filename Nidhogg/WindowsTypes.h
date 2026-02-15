#pragma once
#include "pch.h"

// Documented.
constexpr ULONG64 WIN_1507 = 10240;
constexpr ULONG64 WIN_1511 = 10586;
constexpr ULONG64 WIN_1607 = 14393;
constexpr ULONG64 WIN_1703 = 15063;
constexpr ULONG64 WIN_1709 = 16299;
constexpr ULONG64 WIN_1803 = 17134;
constexpr ULONG64 WIN_1809 = 17763;
constexpr ULONG64 WIN_1903 = 18362;
constexpr ULONG64 WIN_1909 = 18363;
constexpr ULONG64 WIN_2004 = 19041;
constexpr ULONG64 WIN_20H2 = 19042;
constexpr ULONG64 WIN_21H1 = 19043;
constexpr ULONG64 WIN_21H2 = 19044;
constexpr ULONG64 WIN_22H2 = 19045;
constexpr ULONG64 WIN_11_21H2 = 22000;
constexpr ULONG64 WIN_11_22H2 = 22621;
constexpr ULONG64 WIN_11_23H2 = 22631;
constexpr ULONG64 WIN_11_24H2 = 26100;
constexpr ULONG64 WIN_11_25H2 = 26200;
constexpr ULONG64 LATEST_VERSION = WIN_11_24H2;
constexpr ULONG64 SUPPORTED_VERSIONS_COUNT = 19;

constexpr USHORT IMAGE_DOS_SIGNATURE = 0x5A4D;
constexpr ULONG IMAGE_NT_SIGNATURE = 0x00004550;
constexpr USHORT IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
constexpr ULONG IMAGE_REL_AMD64_ADDR64 = 0x0001;
constexpr ULONG IMAGE_REL_AMD64_ADDR32NB = 0x0003;
constexpr ULONG IMAGE_REL_AMD64_REL32 = 0x0004;
constexpr ULONG IMAGE_REL_AMD64_REL32_5 = 0x0009;

typedef struct _IMAGE_DOS_HEADER {
	USHORT   e_magic;
	USHORT   e_cblp;
	USHORT   e_cp;
	USHORT   e_crlc;
	USHORT   e_cparhdr;
	USHORT   e_minalloc;
	USHORT   e_maxalloc;
	USHORT   e_ss;
	USHORT   e_sp;
	USHORT   e_csum;
	USHORT   e_ip;
	USHORT   e_cs;
	USHORT   e_lfarlc;
	USHORT   e_ovno;
	USHORT   e_res[4];
	USHORT   e_oemid;
	USHORT   e_oeminfo;
	USHORT   e_res2[10];
	LONG   e_lfanew;
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	USHORT    Machine;
	USHORT    NumberOfSections;
	ULONG   TimeDateStamp;
	ULONG   PointerToSymbolTable;
	ULONG   NumberOfSymbols;
	USHORT    SizeOfOptionalHeader;
	USHORT    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	ULONG   VirtualAddress;
	ULONG   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	ULONG   Characteristics;
	ULONG   TimeDateStamp;
	USHORT   MajorVersion;
	USHORT   MinorVersion;
	ULONG   Name;
	ULONG   Base;
	ULONG   NumberOfFunctions;
	ULONG   NumberOfNames;
	ULONG   AddressOfFunctions;
	ULONG   AddressOfNames;
	ULONG   AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
	USHORT        Magic;
	UCHAR        MajorLinkerVersion;
	UCHAR        MinorLinkerVersion;
	ULONG       SizeOfCode;
	ULONG       SizeOfInitializedData;
	ULONG       SizeOfUninitializedData;
	ULONG       AddressOfEntryPoint;
	ULONG       BaseOfCode;
	ULONGLONG   ImageBase;
	ULONG       SectionAlignment;
	ULONG       FileAlignment;
	USHORT      MajorOperatingSystemVersion;
	USHORT      MinorOperatingSystemVersion;
	USHORT      MajorImageVersion;
	USHORT      MinorImageVersion;
	USHORT      MajorSubsystemVersion;
	USHORT      MinorSubsystemVersion;
	ULONG       Win32VersionValue;
	ULONG       SizeOfImage;
	ULONG       SizeOfHeaders;
	ULONG       CheckSum;
	USHORT      Subsystem;
	USHORT      DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	ULONG       LoaderFlags;
	ULONG       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, * PIMAGE_OPTIONAL_HEADER;

typedef struct _FULL_IMAGE_NT_HEADERS {
	ULONG Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
} FULL_IMAGE_NT_HEADERS, * PFULL_IMAGE_NT_HEADERS;

typedef struct _IMAGE_SECTION_HEADER
{
	UCHAR  Name[8];
	union
	{
		ULONG PhysicalAddress;
		ULONG VirtualSize;
	} Misc;
	ULONG VirtualAddress;
	ULONG SizeOfRawData;
	ULONG PointerToRawData;
	ULONG PointerToRelocations;
	ULONG PointerToLinenumbers;
	USHORT  NumberOfRelocations;
	USHORT  NumberOfLinenumbers;
	ULONG Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

#pragma warning(default : 4214)

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;                                                      //0x4
	PVOID SsHandle;                                                         //0x8
	LIST_ENTRY InLoadOrderModuleList;                               //0x10
	LIST_ENTRY InMemoryOrderModuleList;                             //0x20
	LIST_ENTRY InInitializationOrderModuleList;                     //0x30
	PVOID EntryInProgress;                                                  //0x40
	UCHAR ShutdownInProgress;                                               //0x48
	PVOID ShutdownThreadId;                                                 //0x50
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	VOID* ExceptionTable;
	ULONG ExceptionTableSize;
	VOID* GpValue;
	PVOID* NonPagedDebugInfo;
	VOID* DllBase;
	VOID* EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;

	union
	{
		USHORT SignatureLevel : 4;
		USHORT SignatureType : 3;
		USHORT Frozen : 2;
		USHORT HotPatch : 1;
		USHORT Unused : 6;
		USHORT EntireField;
	} u1;
	VOID* SectionPointer;
	ULONG CheckSum;
	ULONG CoverageSectionSize;
	VOID* CoverageSection;
	VOID* LoadedImports;
	union
	{
		VOID* Spare;
		PVOID* NtDataTableEntry;
	};
	ULONG SizeOfImageNotRounded;
	ULONG TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	UCHAR          Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _REAL_PEB {
	UCHAR Reserved1[2];
	UCHAR BeingDebugged;
	UCHAR Reserved2[21];
	PPEB_LDR_DATA LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	UCHAR Reserved3[520];
	PVOID PostProcessInitRoutine;
	UCHAR Reserved4[136];
	ULONG SessionId;
} REALPEB, * PREALPEB;

// Undocumented.
extern "C" POBJECT_TYPE* IoDriverObjectType;

extern "C" PKLDR_DATA_TABLE_ENTRY PsLoadedModuleList;
extern "C" PERESOURCE PsLoadedModuleResource;

typedef struct _TRACE_ENABLE_INFO
{
	ULONG IsEnabled;                                                        //0x0
	UCHAR Level;                                                            //0x4
	UCHAR Reserved1;                                                        //0x5
	USHORT LoggerId;                                                        //0x6
	ULONG EnableProperty;                                                   //0x8
	ULONG Reserved2;                                                        //0xc
	ULONGLONG MatchAnyKeyword;                                              //0x10
	ULONGLONG MatchAllKeyword;                                              //0x18
} TRACE_ENABLE_INFO, * PTRACE_ENABLE_INFO;

typedef struct _CM_CALLBACK {
	LIST_ENTRY List;
	ULONG64 Unknown1[2];
	ULONG64 Context;
	ULONG64 Function;
	UNICODE_STRING Altitude;
	ULONG64 Unknown2[2];
} CM_CALLBACK, * PCM_CALLBACK;

typedef VOID(*PKNORMAL_ROUTINE) (
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2);

typedef VOID(*PKKERNEL_ROUTINE) (
	PKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2);

typedef VOID(*PKRUNDOWN_ROUTINE) (
	PKAPC Apc);

typedef struct _PS_PROTECTION
{
	UCHAR Type : 3;
	UCHAR Audit : 1;
	UCHAR Signer : 4;
} PS_PROTECTION, * PPS_PROTECTION;

typedef struct _PROCESS_SIGNATURE
{
	UCHAR SignatureLevel;
	UCHAR SectionSignatureLevel;
	PS_PROTECTION Protection;
} PROCESS_SIGNATURE, * PPROCESS_SIGNATURE;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

enum SignatureType
{
	PsProtectedTypeNone = 0,
	PsProtectedTypeProtectedLight = 1,
	PsProtectedTypeProtected = 2
};

enum SignatureSigner
{
	PsProtectedSignerNone = 0,      // 0
	PsProtectedSignerAuthenticode,  // 1
	PsProtectedSignerCodeGen,       // 2
	PsProtectedSignerAntimalware,   // 3
	PsProtectedSignerLsa,           // 4
	PsProtectedSignerWindows,       // 5
	PsProtectedSignerWinTcb,        // 6
	PsProtectedSignerWinSystem,     // 7
	PsProtectedSignerApp,           // 8
	PsProtectedSignerMax            // 9
};

enum KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
};

enum SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemProcessInformation = 5,
	SystemCallCountInformation = 6,
	SystemDeviceInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemFlagsInformation = 9,
	SystemCallTimeInformation = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemStackTraceInformation = 13,
	SystemPagedPoolInformation = 14,
	SystemNonPagedPoolInformation = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemVdmBopInformation = 20,
	SystemFileCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemDpcBehaviorInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemLoadGdiDriverInformation = 26,
	SystemUnloadGdiDriverInformation = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemSummaryMemoryInformation = 29,
	SystemMirrorMemoryInformation = 30,
	SystemPerformanceTraceInformation = 31,
	SystemObsolete0 = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemExtendServiceTableInformation = 38,
	SystemPrioritySeperation = 39,
	SystemVerifierAddDriverInformation = 40,
	SystemVerifierRemoveDriverInformation = 41,
	SystemProcessorIdleInformation = 42,
	SystemLegacyDriverInformation = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemTimeSlipNotification = 46,
	SystemSessionCreate = 47,
	SystemSessionDetach = 48,
	SystemSessionInformation = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemVerifierThunkExtend = 52,
	SystemSessionProcessInformation = 53,
	SystemLoadGdiDriverInSystemSpace = 54,
	SystemNumaProcessorMap = 55,
	SystemPrefetcherInformation = 56,
	SystemExtendedProcessInformation = 57,
	SystemRecommendedSharedDataAlignment = 58,
	SystemComPlusPackage = 59,
	SystemNumaAvailableMemory = 60,
	SystemProcessorPowerInformation = 61,
	SystemEmulationBasicInformation = 62,
	SystemEmulationProcessorInformation = 63,
	SystemExtendedHandleInformation = 64,
	SystemLostDelayedWriteInformation = 65,
	SystemBigPoolInformation = 66,
	SystemSessionPoolTagInformation = 67,
	SystemSessionMappedViewInformation = 68,
	SystemHotpatchInformation = 69,
	SystemObjectSecurityMode = 70,
	SystemWatchdogTimerHandler = 71,
	SystemWatchdogTimerInformation = 72,
	SystemLogicalProcessorInformation = 73,
	SystemWow64SharedInformationObsolete = 74,
	SystemRegisterFirmwareTableInformationHandler = 75,
	SystemFirmwareTableInformation = 76,
	SystemModuleInformationEx = 77,
	SystemVerifierTriageInformation = 78,
	SystemSuperfetchInformation = 79,
	SystemMemoryListInformation = 80,
	SystemFileCacheInformationEx = 81,
	SystemThreadPriorityClientIdInformation = 82,
	SystemProcessorIdleCycleTimeInformation = 83,
	SystemVerifierCancellationInformation = 84,
	SystemProcessorPowerInformationEx = 85,
	SystemRefTraceInformation = 86,
	SystemSpecialPoolInformation = 87,
	SystemProcessIdInformation = 88,
	SystemErrorPortInformation = 89,
	SystemBootEnvironmentInformation = 90,
	SystemHypervisorInformation = 91,
	SystemVerifierInformationEx = 92,
	SystemTimeZoneInformation = 93,
	SystemImageFileExecutionOptionsInformation = 94,
	SystemCoverageInformation = 95,
	SystemPrefetchPatchInformation = 96,
	SystemVerifierFaultsInformation = 97,
	SystemSystemPartitionInformation = 98,
	SystemSystemDiskInformation = 99,
	SystemProcessorPerformanceDistribution = 100,
	SystemNumaProximityNodeInformation = 101,
	SystemDynamicTimeZoneInformation = 102,
	SystemCodeIntegrityInformation = 103,
	SystemProcessorMicrocodeUpdateInformation = 104,
	SystemProcessorBrandString = 105,
	SystemVirtualAddressInformation = 106,
	SystemLogicalProcessorAndGroupInformation = 107,
	SystemProcessorCycleTimeInformation = 108,
	SystemStoreInformation = 109,
	SystemRegistryAppendString = 110,
	SystemAitSamplingValue = 111,
	SystemVhdBootInformation = 112,
	SystemCpuQuotaInformation = 113,
	SystemNativeBasicInformation = 114,
	SystemErrorPortTimeouts = 115,
	SystemLowPriorityIoInformation = 116,
	SystemBootEntropyInformation = 117,
	SystemVerifierCountersInformation = 118,
	SystemPagedPoolInformationEx = 119,
	SystemSystemPtesInformationEx = 120,
	SystemNodeDistanceInformation = 121,
	SystemAcpiAuditInformation = 122,
	SystemBasicPerformanceInformation = 123,
	SystemQueryPerformanceCounterInformation = 124,
	SystemSessionBigPoolInformation = 125,
	SystemBootGraphicsInformation = 126,
	SystemScrubPhysicalMemoryInformation = 127,
	SystemBadPageInformation = 128,
	SystemProcessorProfileControlArea = 129,
	SystemCombinePhysicalMemoryInformation = 130,
	SystemEntropyInterruptTimingInformation = 131,
	SystemConsoleInformation = 132,
	SystemPlatformBinaryInformation = 133,
	SystemPolicyInformation = 134,
	SystemHypervisorProcessorCountInformation = 135,
	SystemDeviceDataInformation = 136,
	SystemDeviceDataEnumerationInformation = 137,
	SystemMemoryTopologyInformation = 138,
	SystemMemoryChannelInformation = 139,
	SystemBootLogoInformation = 140,
	SystemProcessorPerformanceInformationEx = 141,
	SystemCriticalProcessErrorLogInformation = 142,
	SystemSecureBootPolicyInformation = 143,
	SystemPageFileInformationEx = 144,
	SystemSecureBootInformation = 145,
	SystemEntropyInterruptTimingRawInformation = 146,
	SystemPortableWorkspaceEfiLauncherInformation = 147,
	SystemFullProcessInformation = 148,
	SystemKernelDebuggerInformationEx = 149,
	SystemBootMetadataInformation = 150,
	SystemSoftRebootInformation = 151,
	SystemElamCertificateInformation = 152,
	SystemOfflineDumpConfigInformation = 153,
	SystemProcessorFeaturesInformation = 154,
	SystemRegistryReconciliationInformation = 155,
	SystemEdidInformation = 156,
	SystemManufacturingInformation = 157,
	SystemEnergyEstimationConfigInformation = 158,
	SystemHypervisorDetailInformation = 159,
	SystemProcessorCycleStatsInformation = 160,
	SystemVmGenerationCountInformation = 161,
	SystemTrustedPlatformModuleInformation = 162,
	SystemKernelDebuggerFlags = 163,
	SystemCodeIntegrityPolicyInformation = 164,
	SystemIsolatedUserModeInformation = 165,
	SystemHardwareSecurityTestInterfaceResultsInformation = 166,
	SystemSingleModuleInformation = 167,
	SystemAllowedCpuSetsInformation = 168,
	SystemVsmProtectionInformation = 169,
	SystemInterruptCpuSetsInformation = 170,
	SystemSecureBootPolicyFullInformation = 171,
	SystemCodeIntegrityPolicyFullInformation = 172,
	SystemAffinitizedInterruptProcessorInformation = 173,
	SystemRootSiloInformation = 174,
	SystemCpuSetInformation = 175,
	SystemCpuSetTagInformation = 176,
	SystemWin32WerStartCallout = 177,
	SystemSecureKernelProfileInformation = 178,
	SystemCodeIntegrityPlatformManifestInformation = 179,
	SystemInterruptSteeringInformation = 180,
	SystemSupportedProcessorArchitectures = 181,
	SystemMemoryUsageInformation = 182,
	SystemCodeIntegrityCertificateInformation = 183,
	SystemPhysicalMemoryInformation = 184,
	SystemControlFlowTransition = 185,
	SystemKernelDebuggingAllowed = 186,
	SystemActivityModerationExeState = 187,
	SystemActivityModerationUserSettings = 188,
	SystemCodeIntegrityPoliciesFullInformation = 189,
	SystemCodeIntegrityUnlockInformation = 190,
	SystemIntegrityQuotaInformation = 191,
	SystemFlushInformation = 192,
	SystemProcessorIdleMaskInformation = 193,
	SystemSecureDumpEncryptionInformation = 194,
	SystemWriteConstraintInformation = 195,
	SystemKernelVaShadowInformation = 196,
	SystemHypervisorSharedPageInformation = 197,
	SystemFirmwareBootPerformanceInformation = 198,
	SystemCodeIntegrityVerificationInformation = 199,
	SystemFirmwarePartitionInformation = 200,
	SystemSpeculationControlInformation = 201,
	SystemDmaGuardPolicyInformation = 202,
	SystemEnclaveLaunchControlInformation = 203,
	SystemWorkloadAllowedCpuSetsInformation = 204,
	SystemCodeIntegrityUnlockModeInformation = 205,
	SystemLeapSecondInformation = 206,
	SystemFlags2Information = 207,
	SystemSecurityModelInformation = 208,
	SystemCodeIntegritySyntheticCacheInformation = 209,
	SystemFeatureConfigurationInformation = 210,
	SystemFeatureConfigurationSectionInformation = 211,
	SystemFeatureUsageSubscriptionInformation = 212,
	SystemSecureSpeculationControlInformation = 213,
	SystemSpacesBootInformation = 214,
	SystemFwRamdiskInformation = 215,
	SystemWheaIpmiHardwareInformation = 216,
	SystemDifSetRuleClassInformation = 217,
	SystemDifClearRuleClassInformation = 218,
	SystemDifApplyPluginVerificationOnDriver = 219,
	SystemDifRemovePluginVerificationOnDriver = 220,
	SystemShadowStackInformation = 221,
	SystemBuildVersionInformation = 222,
	SystemPoolLimitInformation = 223,
	SystemCodeIntegrityAddDynamicStore = 224,
	SystemCodeIntegrityClearDynamicStores = 225,
	SystemDifPoolTrackingInformation = 226,
	SystemPoolZeroingInformation = 227,
	SystemDpcWatchdogInformation = 228,
	SystemDpcWatchdogInformation2 = 229,
	SystemSupportedProcessorArchitectures2 = 230,
	SystemSingleProcessorRelationshipInformation = 231,
	SystemXfgCheckFailureInformation = 232,
	SystemIommuStateInformation = 233,
	SystemHypervisorMinrootInformation = 234,
	SystemHypervisorBootPagesInformation = 235,
	SystemPointerAuthInformation = 236,
	SystemSecureKernelDebuggerInformation = 237,
	SystemOriginalImageFeatureInformation = 238,
	MaxSystemInfoClass = 239
};

#pragma warning (disable: 4201)
struct _EX_PUSH_LOCK
{
	union
	{
		struct
		{
			ULONGLONG Locked : 1;
			ULONGLONG Waiting : 1;
			ULONGLONG Waking : 1;
			ULONGLONG MultipleShared : 1;
			ULONGLONG Shared : 60;
		};
		ULONGLONG Value;
		VOID* Ptr;
	};
};

typedef struct _FULL_OBJECT_TYPE {
	LIST_ENTRY TypeList;
	UNICODE_STRING Name;
	VOID* DefaultObject;
	UCHAR Index;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	UCHAR TypeInfo[0x78];
	_EX_PUSH_LOCK TypeLock;
	ULONG Key;
	LIST_ENTRY CallbackList;
} FULL_OBJECT_TYPE, * PFULL_OBJECT_TYPE;


typedef struct _OB_CALLBACK OB_CALLBACK;

typedef struct _OB_CALLBACK_ENTRY {
	LIST_ENTRY CallbackList;
	OB_OPERATION Operations;
	BOOLEAN Enabled;
	OB_CALLBACK* Entry;
	POBJECT_TYPE ObjectType;
	POB_PRE_OPERATION_CALLBACK PreOperation;
	POB_POST_OPERATION_CALLBACK PostOperation;
	KSPIN_LOCK Lock;
} OB_CALLBACK_ENTRY, * POB_CALLBACK_ENTRY;

typedef struct _OB_CALLBACK {
	USHORT Version;
	USHORT OperationRegistrationCount;
	PVOID RegistrationContext;
	UNICODE_STRING AltitudeString;
	OB_CALLBACK_ENTRY EntryItems[1];
	WCHAR AltitudeBuffer[1];
} OB_CALLBACK;

typedef struct _PS_ROUTINE {
	ULONG64 RoutineAddress;
	DWORD RoutineFlags;
} PS_ROUTINE, * PPS_ROUTINE;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE
{
	PULONG_PTR ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG_PTR NumberOfServices;
	PUCHAR ParamTableBase;
} SYSTEM_SERVICE_DESCRIPTOR_TABLE, * PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

typedef struct _MMVAD_FLAGS
{
	ULONG Lock : 1;
	ULONG LockContended : 1;
	ULONG DeleteInProgress : 1;
	ULONG NoChange : 1;
	ULONG VadType : 3;
	ULONG Protection : 5;
	ULONG PreferredNode : 7;
	ULONG PageSize : 2;
	ULONG PrivateMemory : 1;
} MMVAD_FLAGS;

typedef enum _MI_VAD_TYPE
{
	VadNone = 0,
	VadDevicePhysicalMemory = 1,
	VadImageMap = 2,
	VadAwe = 3,
	VadWriteWatch = 4,
	VadLargePages = 5,
	VadRotatePhysical = 6,
	VadLargePageSection = 7
} MI_VAD_TYPE;

typedef struct _MM_PRIVATE_VAD_FLAGS
{
	ULONG Lock : 1;
	ULONG LockContended : 1;
	ULONG DeleteInProgress : 1;
	ULONG NoChange : 1;
	ULONG VadType : 3;
	ULONG Protection : 5;
	ULONG PreferredNode : 7;
	ULONG PageSize : 2;
	ULONG PrivateMemoryAlwaysSet : 1;
	ULONG WriteWatch : 1;
	ULONG FixedLargePageSize : 1;
	ULONG ZeroFillPagesOptional : 1;
	ULONG Graphics : 1;
	ULONG Enclave : 1;
	ULONG ShadowStack : 1;
	ULONG PhysicalMemoryPfnsReferenced : 1;
} MM_PRIVATE_VAD_FLAGS;

typedef struct _MM_GRAPHICS_VAD_FLAGS
{
	ULONG Lock : 1;
	ULONG LockContended : 1;
	ULONG DeleteInProgress : 1;
	ULONG NoChange : 1;
	ULONG VadType : 3;
	ULONG Protection : 5;
	ULONG PreferredNode : 7;
	ULONG PageSize : 2;
	ULONG PrivateMemoryAlwaysSet : 1;
	ULONG WriteWatch : 1;
	ULONG FixedLargePageSize : 1;
	ULONG ZeroFillPagesOptional : 1;
	ULONG GraphicsAlwaysSet : 1;
	ULONG GraphicsUseCoherentBus : 1;
	ULONG GraphicsNoCache : 1;
	ULONG GraphicsPageProtection : 3;
} MM_GRAPHICS_VAD_FLAGS;

typedef struct _MM_SHARED_VAD_FLAGS
{
	ULONG Lock : 1;
	ULONG LockContended : 1;
	ULONG DeleteInProgress : 1;
	ULONG NoChange : 1;
	ULONG VadType : 3;
	ULONG Protection : 5;
	ULONG PreferredNode : 7;
	ULONG PageSize : 2;
	ULONG PrivateMemoryAlwaysClear : 1;
	ULONG PrivateFixup : 1;
	ULONG HotPatchState : 2;
} MM_SHARED_VAD_FLAGS;

typedef struct _MMVAD_FLAGS1
{
	ULONG CommitCharge : 31;
	ULONG MemCommit : 1;
} MMVAD_FLAGS1;

typedef struct _MMVAD_FLAGS2
{
	ULONG FileOffset : 24;
	ULONG Large : 1;
	ULONG TrimBehind : 1;
	ULONG Inherit : 1;
	ULONG NoValidationNeeded : 1;
	ULONG PrivateDemandZero : 1;
	ULONG Spare : 3;
} MMVAD_FLAGS2;


typedef struct _EX_FAST_REF
{
	union
	{
		VOID* Object;
		ULONGLONG RefCnt : 4;
		ULONGLONG Value;
	};
} EX_FAST_REF;

typedef struct _MMEXTEND_INFO
{
	ULONGLONG CommittedSize;
	ULONG ReferenceCount;
} MMEXTEND_INFO;

typedef struct _MI_VAD_SEQUENTIAL_INFO
{
	ULONGLONG Length : 12;
	ULONGLONG Vpn : 52;
} MI_VAD_SEQUENTIAL_INFO;

typedef struct _IMAGE_SECURITY_CONTEXT
{
	union
	{
		VOID* PageHashes;
		ULONGLONG Value;
		struct
		{
			ULONGLONG SecurityBeingCreated : 2;
			ULONGLONG SecurityMandatory : 1;
			ULONGLONG PageHashPointer : 61;
		};
	};
} IMAGE_SECURITY_CONTEXT;

typedef struct _MI_IMAGE_SECURITY_REFERENCE
{
	VOID* DynamicRelocations;
	IMAGE_SECURITY_CONTEXT SecurityContext;
	ULONGLONG StrongImageReference;
} MI_IMAGE_SECURITY_REFERENCE;

typedef struct _MMSUBSECTION_FLAGS
{
	USHORT SubsectionAccessed : 1;
	USHORT Protection : 5;
	USHORT StartingSector4132 : 10;
	USHORT SubsectionStatic : 1;
	USHORT GlobalMemory : 1;
	USHORT Spare : 1;
	USHORT OnDereferenceList : 1;
	USHORT SectorEndOffset : 12;
} MMSUBSECTION_FLAGS;

typedef struct _MMPTE
{
	union
	{
		ULONGLONG Long;
		volatile ULONGLONG VolatileLong;
		ULONGLONG Hard;
		ULONGLONG Proto;
		ULONGLONG Soft;
		ULONGLONG TimeStamp;
		ULONGLONG Trans;
		ULONGLONG Subsect;
		ULONGLONG List;
	} u;
} MMPTE;

typedef struct _MI_SUBSECTION_ENTRY1
{
	ULONG CrossPartitionReferences : 30;
	ULONG SubsectionMappedLarge : 2;
} MI_SUBSECTION_ENTRY1;

typedef struct _CONTROL_AREA
{
	PVOID* Segment;
	union
	{
		LIST_ENTRY ListHead;
		VOID* AweContext;
	};
	ULONGLONG NumberOfSectionReferences;
	ULONGLONG NumberOfPfnReferences;
	ULONGLONG NumberOfMappedViews;
	ULONGLONG NumberOfUserReferences;
	union
	{
		ULONG LongFlags;
		ULONG Flags;
	} u;
	union
	{
		ULONG LongFlags;
		ULONG Flags;
	} u1;
	EX_FAST_REF FilePointer;
	volatile LONG ControlAreaLock;
	ULONG ModifiedWriteCount;
	struct _MI_CONTROL_AREA_WAIT_BLOCK* WaitList;
	union
	{
		struct
		{
			union
			{
				ULONG NumberOfSystemCacheViews;
				ULONG ImageRelocationStartBit;
			};
			union
			{
				volatile LONG WritableUserReferences;
				struct
				{
					ULONG ImageRelocationSizeIn64k : 16;
					ULONG SystemImage : 1;
					ULONG CantMove : 1;
					ULONG StrongCode : 2;
					ULONG BitMap : 2;
					ULONG ImageActive : 1;
					ULONG ImageBaseOkToReuse : 1;
				};
			};
			union
			{
				ULONG FlushInProgressCount;
				ULONG NumberOfSubsections;
				MI_IMAGE_SECURITY_REFERENCE* SeImageStub;
			};
		} e2;
	} u2;
	EX_PUSH_LOCK FileObjectLock;
	volatile ULONGLONG LockedPages;
	union
	{
		ULONGLONG IoAttributionContext : 61;
		ULONGLONG Spare : 3;
		ULONGLONG ImageCrossPartitionCharge;
		ULONGLONG CommittedPageCount : 36;
	} u3;
} CONTROL_AREA;

typedef struct _RTL_AVL_TREE
{
	RTL_BALANCED_NODE* Root;                                        //0x0
} RTL_AVL_TREE;

typedef struct _SUBSECTION
{
	CONTROL_AREA* ControlArea;
	MMPTE* SubsectionBase;
	PVOID NextSubsection;
	union
	{
		RTL_AVL_TREE GlobalPerSessionHead;
		PVOID* CreationWaitList;
		PVOID* SessionDriverProtos;
	};
	union
	{
		ULONG LongFlags;                                                    //0x20
		MMSUBSECTION_FLAGS SubsectionFlags;                         //0x20
	} u;                                                                    //0x20
	ULONG StartingSector;                                                   //0x24
	ULONG NumberOfFullSectors;                                              //0x28
	ULONG PtesInSubsection;                                                 //0x2c
	union
	{
		MI_SUBSECTION_ENTRY1 e1;                                    //0x30
		ULONG EntireField;                                                  //0x30
	} u1;                                                                   //0x30
	ULONG UnusedPtes : 30;                                                    //0x34
	ULONG ExtentQueryNeeded : 1;                                              //0x34
	ULONG DirtyPages : 1;                                                     //0x34
} SUBSECTION, * PSUBSECTION;

typedef struct _MMVAD_SHORT
{
	union
	{
		struct
		{
			PVOID NextVad;
			PVOID ExtraCreateInfo;
		};
		RTL_BALANCED_NODE VadNode;
	};
	ULONG StartingVpn;
	ULONG EndingVpn;
	UCHAR StartingVpnHigh;
	UCHAR EndingVpnHigh;
	UCHAR CommitChargeHigh;
	UCHAR SpareNT64VadUChar;
	LONG ReferenceCount;
	EX_PUSH_LOCK PushLock;
	union
	{
		ULONG LongFlags;
		MMVAD_FLAGS VadFlags;
		MM_PRIVATE_VAD_FLAGS PrivateVadFlags;
		MM_GRAPHICS_VAD_FLAGS GraphicsVadFlags;
		MM_SHARED_VAD_FLAGS SharedVadFlags;
		volatile ULONG VolatileVadLong;
	} u;
	union
	{
		ULONG LongFlags1;
		MMVAD_FLAGS1 VadFlags1;
	} u1;
	union
	{
		ULONGLONG EventListULongPtr;
		UCHAR StartingVpnHigher : 4;
	} u5;
} MMVAD_SHORT, * PMMVAD_SHORT;

typedef struct _MMVAD
{
	MMVAD_SHORT Core;
	union
	{
		ULONG LongFlags2;
		MMVAD_FLAGS2 VadFlags2;
	} u2;
	SUBSECTION* Subsection;
	MMPTE* FirstPrototypePte;
	MMPTE* LastContiguousPte;
	LIST_ENTRY ViewLinks;
	PEPROCESS VadsProcess;
	union
	{
		MI_VAD_SEQUENTIAL_INFO SequentialVa;
		MMEXTEND_INFO* ExtendedInfo;
	} u4;
	FILE_OBJECT* FileObject;
} MMVAD, * PMMVAD;

typedef struct _PRIMARY_CREDENTIALS {
	struct _PRIMARY_CREDENTIALS* next;
	ANSI_STRING Primary;
	LSA_UNICODE_STRING Credentials;
} PRIMARY_CREDENTIALS, * PPRIMARY_CREDENTIALS;

typedef struct _MSV1_0_CREDENTIALS {
	struct _MSV1_0_CREDENTIALS* next;
	ULONG AuthenticationPackageId;
	PPRIMARY_CREDENTIALS PrimaryCredentials;
} MSV1_0_CREDENTIALS, * PMSV1_0_CREDENTIALS;

#pragma pack(push, 8)
typedef struct _RTL_CRITICAL_SECTION
{
	PVOID DebugInfo;
	LONG LockCount;
	LONG RecursionCount;
	HANDLE OwningThread;
	HANDLE LockSemaphore;
	ULONG_PTR SpinCount;
} RTL_CRITICAL_SECTION, * PRTL_CRITICAL_SECTION;
#pragma pack(pop)

typedef struct _RTL_RESOURCE
{
	RTL_CRITICAL_SECTION Lock;
	HANDLE SharedSemaphore;
	ULONG SharedWaiters;
	HANDLE ExclusiveSemaphore;
	ULONG ExclusiveWaiters;
	LONG NumberActive;
	HANDLE OwningThread;
	ULONG TimeoutBoost;
	PVOID DebugInfo;
} RTL_RESOURCE, * PRTL_RESOURCE;

typedef struct _LSASRV_CREDENTIALS {
	LIST_ENTRY Entry;
	RTL_RESOURCE Resource;
	LUID LogonId;
	LUID SecondaryLogonId;
	UCHAR pad[12];
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domain;
	PVOID unk14;
	PVOID unk15;
	LSA_UNICODE_STRING Type;
	PSID  pSid;
	ULONG LogonType;
	PVOID unk18;
	ULONG Session;
	LARGE_INTEGER LogonTime;
	LSA_UNICODE_STRING LogonServer;
	PMSV1_0_CREDENTIALS Credentials;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	ULONG unk23;
	ULONG unk24;
	ULONG unk25;
	ULONG unk26;
	PVOID unk27;
	PVOID unk28;
	PVOID unk29;
	PVOID CredentialManager;
} LSASRV_CREDENTIALS, * PLSASRV_CREDENTIALS;

typedef struct _LSASRV_CREDENTIALS_WIN23H2 {
	LIST_ENTRY      Entry;
	RTL_RESOURCE	Resource;
	LUID            LogonId;
	LUID            SecondaryLogonId;
	UCHAR           unk14[32];
	UNICODE_STRING  UserName;
	UNICODE_STRING  Domain;
	PVOID           unk15;
	PVOID           unk16;
	UNICODE_STRING  Type;
	PSID            Sid;
	ULONG           LogonType;
	ULONG           _pad2;
	PVOID           unk18;
	ULONG           Session;
	ULONG           _pad3;
	LARGE_INTEGER   LogonTime;
	UNICODE_STRING  LogonServer;
	PMSV1_0_CREDENTIALS Credentials;
	PVOID           unk19;
	PVOID           unk20;
	ULONG 		    unk21;
	ULONG 			_pad4;
	ULONG           unk22;
	ULONG           unk23;
	LARGE_INTEGER   unk24;
	ULONG           unk25;
	ULONG           _pad5;
	PVOID           unk26;
	PVOID           unk27;
	ULONG           unk28;
	ULONG           _pad6;
	PVOID           unk29;
	PVOID           CredentialManager;
	ULONG           unk31;
	ULONG           _pad7;
	ULONG           unk32;
	ULONG           _pad8;
	PVOID           unk33;
	PVOID           unk34;
	PVOID           LsapDsNameMap;
	PVOID           unk36;
	UCHAR            unk37[0x98];
	ULONG           Flags;
	ULONG           _pad9;
	UCHAR            unk38[0x48];
	LARGE_INTEGER   ExpirationTime;
	LARGE_INTEGER   unk39;
	LARGE_INTEGER   PasswordLastSet;
	LARGE_INTEGER   PasswordCanChange;
	LARGE_INTEGER   PasswordMustChange;
	ULONG           unk40;
} LSASRV_CREDENTIALS_WIN23H2, * PLSASRV_CREDENTIALS_WIN23H2;

typedef struct _HARD_KEY {
	ULONG cbSecret;
	UCHAR data[ANYSIZE_ARRAY];
} HARD_KEY, * PHARD_KEY;

typedef struct _BCRYPT_KEY {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	ULONG unk3;
	ULONG unk4;
	PVOID unk5;	// before, align in x64
	ULONG unk6;
	ULONG unk7;
	ULONG unk8;
	ULONG unk9;
	HARD_KEY hardkey;
} BCRYPT_KEY, * PBCRYPT_KEY;

typedef struct _BCRYPT_HANDLE_KEY {
	ULONG size;
	ULONG tag;	// 'UUUR'
	PVOID hAlgorithm;
	PBCRYPT_KEY key;
	PVOID unk0;
} BCRYPT_HANDLE_KEY, * PBCRYPT_HANDLE_KEY;

typedef struct _BCRYPT_GEN_KEY {
	PBCRYPT_HANDLE_KEY hKey;
	PVOID hProvider;
	PUCHAR pKey;
	ULONG cbKey;
} BCRYPT_GEN_KEY, * PBCRYPT_GEN_KEY;

typedef enum _COMUNICATION_TYPE
{
	UDP = 1,
	TCP = 3
} COMUNICATION_TYPE;

typedef struct _NSI_TCP_ENTRY
{
	UCHAR Reserved1[2];
	USHORT Port;
	ULONG IpAddress;
	UCHAR IpAddress6[16];
	UCHAR Reserved2[4];
} NSI_TCP_ENTRY, * PNSI_TCP_ENTRY;

typedef struct _NSI_TABLE_TCP_ENTRY
{
	NSI_TCP_ENTRY Local;
	NSI_TCP_ENTRY Remote;
} NSI_TABLE_TCP_ENTRY, * PNSI_TABLE_TCP_ENTRY;

typedef struct _NSI_UDP_ENTRY
{
	UCHAR Reserved1[2];
	USHORT Port;
	ULONG IpAddress;
	UCHAR IpAddress6[16];
	UCHAR Reserved2[4];
} NSI_UDP_ENTRY, * PNSI_UDP_ENTRY;

typedef struct _NSI_STATUS_ENTRY
{
	ULONG State;
	UCHAR Reserved[8];
} NSI_STATUS_ENTRY, * PNSI_STATUS_ENTRY;

typedef struct _NSI_PROCESS_ENTRY
{
	ULONG UdpProcessId;
	ULONG Reserved1;
	ULONG Reserved2;
	ULONG TcpProcessId;
	ULONG Reserved3;
	ULONG Reserved4;
	ULONG Reserved5;
	ULONG Reserved6;
} NSI_PROCESS_ENTRY, * PNSI_PROCESS_ENTRY;

typedef struct _NSI_PARAM
{
	SIZE_T Reserved1;
	SIZE_T Reserved2;
	PVOID ModuleId;
	COMUNICATION_TYPE Type;
	ULONG Reserved3;
	ULONG Reserved4;
	PVOID Entries;
	SIZE_T EntrySize;
	PVOID Reserved5;
	SIZE_T Reserved6;
	PNSI_STATUS_ENTRY StatusEntries;
	SIZE_T Reserved7;
	PNSI_PROCESS_ENTRY ProcessEntries;
	SIZE_T ProcessEntrySize;
	SIZE_T Count;
} NSI_PARAM, * PNSI_PARAM;

// Prototypes
typedef NTSTATUS(NTAPI* tNtfsIrpFunction)(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp);

typedef NTSTATUS(NTAPI* tIoCreateDriver)(
	PUNICODE_STRING DriverName,
	PDRIVER_INITIALIZE InitializationFunction);

typedef ULONG(NTAPI* PTHREAD_START_ROUTINE)(
	PVOID lpThreadParameter);

typedef NTSTATUS(NTAPI* tNtCreateThreadEx)(
	PHANDLE hThread,
	ACCESS_MASK DesiredAccess,
	PVOID ObjectAttributes,
	HANDLE ProcessHandle,
	PTHREAD_START_ROUTINE lpStartAddress,
	PVOID lpParameter,
	ULONG Flags,
	SIZE_T StackZeroBits,
	SIZE_T SizeOfStackCommit,
	SIZE_T SizeOfStackReserve,
	PVOID lpBytesBuffer);

typedef PVOID(NTAPI* tExAllocatePool2)(
	POOL_FLAGS Flags,
	SIZE_T     NumberOfBytes,
	ULONG      Tag
	);

typedef _Function_class_(USER_THREAD_START_ROUTINE)
NTSTATUS NTAPI USER_THREAD_START_ROUTINE(
	_In_ PVOID ThreadParameter
);
typedef USER_THREAD_START_ROUTINE* PUSER_THREAD_START_ROUTINE;

extern "C" {
	PVOID NTAPI PsGetCurrentProcessWow64Process();

	PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);

	NTSTATUS NTAPI ZwQuerySystemInformation(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength);

	NTSTATUS NTAPI ZwProtectVirtualMemory(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		SIZE_T* NumberOfBytesToProtect,
		ULONG NewAccessProtection,
		PULONG OldAccessProtection);

	NTSTATUS NTAPI MmCopyVirtualMemory(
		PEPROCESS SourceProcess,
		PVOID SourceAddress,
		PEPROCESS TargetProcess,
		PVOID TargetAddress,
		SIZE_T BufferSize,
		KPROCESSOR_MODE PreviousMode,
		PSIZE_T ReturnSize);

	NTSTATUS NTAPI ObReferenceObjectByName(
		PUNICODE_STRING ObjectName,
		ULONG Attributes,
		PACCESS_STATE AccessState,
		ACCESS_MASK DesiredAccess,
		POBJECT_TYPE ObjectType,
		KPROCESSOR_MODE AccessMode,
		PVOID ParseContext,
		PVOID* Object);

	VOID NTAPI KeInitializeApc(
		PKAPC Apc,
		PKTHREAD Thread,
		KAPC_ENVIRONMENT Environment,
		PKKERNEL_ROUTINE KernelRoutine,
		PKRUNDOWN_ROUTINE RundownRoutine,
		PKNORMAL_ROUTINE NormalRoutine,
		KPROCESSOR_MODE ApcMode,
		PVOID NormalContext);

	BOOLEAN NTAPI KeInsertQueueApc(
		PKAPC Apc,
		PVOID SystemArgument1,
		PVOID SystemArgument2,
		KPRIORITY Increment);

	BOOLEAN NTAPI KeTestAlertThread(KPROCESSOR_MODE AlertMode);

	NTKERNELAPI
	PVOID
	NTAPI
	RtlFindExportedRoutineByName(
		_In_ PVOID ImageBase,
		_In_ PCCH RoutineName
	);

	NTSTATUS
	NTAPI
	RtlCreateUserThread(
		_In_ HANDLE ProcessHandle,
		_In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
		_In_ BOOLEAN CreateSuspended,
		_In_opt_ ULONG ZeroBits,
		_In_opt_ SIZE_T MaximumStackSize,
		_In_opt_ SIZE_T CommittedStackSize,
		_In_ PUSER_THREAD_START_ROUTINE StartAddress,
		_In_opt_ PVOID Parameter,
		_Out_opt_ PHANDLE ThreadHandle,
		_Out_opt_ PCLIENT_ID ClientId
	);
}
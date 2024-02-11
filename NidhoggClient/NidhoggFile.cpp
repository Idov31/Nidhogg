#include "pch.h"
#include "Nidhogg.h"

NidhoggErrorCodes NidhoggInterface::FileProtect(wchar_t* filePath) {
	DWORD returned;
	ProtectedFile protectedFile = { filePath, true };

	if (wcslen(filePath) > MAX_PATH)
		return NIDHOGG_INVALID_INPUT;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_PROTECT_UNPROTECT_FILE,
		&protectedFile, sizeof(protectedFile),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::FileUnprotect(wchar_t* filePath) {
	DWORD returned;
	ProtectedFile protectedFile = { filePath, false };

	if (!DeviceIoControl(this->hNidhogg, IOCTL_PROTECT_UNPROTECT_FILE,
		&protectedFile, sizeof(protectedFile),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::FileClearAllProtection() {
	DWORD returned;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_CLEAR_FILE_PROTECTION,
		nullptr, 0, nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

std::vector<std::wstring> NidhoggInterface::QueryFiles() {
	DWORD returned;
	FileItem result{};
	std::vector<std::wstring> files;
	int amountOfFiles = 0;
	result.FileIndex = 0;

	if (!DeviceIoControl(hNidhogg, IOCTL_QUERY_FILES,
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

		if (!DeviceIoControl(hNidhogg, IOCTL_QUERY_FILES,
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
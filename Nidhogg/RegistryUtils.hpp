#pragma once
#include "pch.h"

// Definitions.
#define REG_TYPE_KEY 0
#define REG_TYPE_VALUE 1

// Prototypes.
bool FindRegItem(RegItem& item);
bool ContainsProtectedRegKey(UNICODE_STRING regKey, int type);
bool AddRegItem(RegItem& item);
bool RemoveRegItem(RegItem& item);
bool GetNameFromKeyEnumPreInfo(KEY_INFORMATION_CLASS infoClass, PVOID information, PUNICODE_STRING keyName);
bool GetNameFromValueEnumPreInfo(KEY_VALUE_INFORMATION_CLASS infoClass, PVOID information, PUNICODE_STRING keyName);
NTSTATUS RegNtPreDeleteKeyHandler(REG_DELETE_KEY_INFORMATION* info);
NTSTATUS RegNtPreDeleteValueKeyHandler(REG_DELETE_VALUE_KEY_INFORMATION* info);
NTSTATUS RegNtPostEnumerateKeyHandler(REG_POST_OPERATION_INFORMATION* info);
NTSTATUS RegNtPostEnumerateValueKeyHandler(REG_POST_OPERATION_INFORMATION* info);

NTSTATUS OnRegistryNotify(PVOID context, PVOID arg1, PVOID arg2) {
	UNREFERENCED_PARAMETER(context);
	NTSTATUS status = STATUS_SUCCESS;

	// Need to also add: PreQueryValue, PreQueryMultipleValue, SetValueKey
	switch ((REG_NOTIFY_CLASS)(ULONG_PTR)arg1) {
	case RegNtPreDeleteKey:
		status = RegNtPreDeleteKeyHandler(static_cast<REG_DELETE_KEY_INFORMATION*>(arg2));
		break;
	case RegNtPreDeleteValueKey:
		status = RegNtPreDeleteValueKeyHandler(static_cast<REG_DELETE_VALUE_KEY_INFORMATION*>(arg2));
		break;
	case RegNtPostEnumerateKey:
		status = RegNtPostEnumerateKeyHandler(static_cast<REG_POST_OPERATION_INFORMATION*>(arg2));
		break;
	case RegNtPostEnumerateValueKey:
		status = RegNtPostEnumerateValueKeyHandler(static_cast<REG_POST_OPERATION_INFORMATION*>(arg2));
		break;
	}

	return status;
}

NTSTATUS RegNtPreDeleteKeyHandler(REG_DELETE_KEY_INFORMATION* info) {
	RegItem regItem;
	PCUNICODE_STRING regPath;
	NTSTATUS status = STATUS_SUCCESS;

	// To avoid BSOD.
	if (!info->Object || !MmIsAddressValid(info->Object))
		return STATUS_SUCCESS;

	status = CmCallbackGetKeyObjectIDEx(&rGlobals.RegCookie, info->Object, nullptr, &regPath, 0);

	if (!NT_SUCCESS(status)) {
		return STATUS_SUCCESS;
	}

	if (!regPath->Buffer || !MmIsAddressValid(regPath->Buffer)) {
		return STATUS_SUCCESS;
	}
	
	wcsncpy_s(regItem.KeyPath, regPath->Buffer, regPath->Length / sizeof(WCHAR));
	regItem.Type = REG_TYPE_KEY;

	if (FindRegItem(regItem)) {
		auto prevIrql = KeGetCurrentIrql();
		KeLowerIrql(PASSIVE_LEVEL);
		KdPrint((DRIVER_PREFIX "Protected key %ws\n", regItem.KeyPath));
		KeRaiseIrql(prevIrql, &prevIrql);
		status = STATUS_ACCESS_DENIED;
	}

	CmCallbackReleaseKeyObjectIDEx(regPath);
	return status;
}

NTSTATUS RegNtPreDeleteValueKeyHandler(REG_DELETE_VALUE_KEY_INFORMATION* info) {
	RegItem regItem;
	PCUNICODE_STRING regPath;
	NTSTATUS status = STATUS_SUCCESS;

	// To avoid BSOD.
	if (!MmIsAddressValid(info->Object))
		return STATUS_SUCCESS;

	status = CmCallbackGetKeyObjectIDEx(&rGlobals.RegCookie, info->Object, nullptr, &regPath, 0);

	if (!NT_SUCCESS(status)) {
		return STATUS_SUCCESS;
	}

	if (!regPath->Buffer || !MmIsAddressValid(regPath->Buffer)) {
		return STATUS_SUCCESS;
	}
	
	wcsncpy_s(regItem.KeyPath, regPath->Buffer, regPath->Length / sizeof(WCHAR));
	wcsncpy_s(regItem.ValueName, info->ValueName->Buffer, info->ValueName->Length / sizeof(WCHAR));
	regItem.Type = REG_TYPE_VALUE;

	if (FindRegItem(regItem)) {
		auto prevIrql = KeGetCurrentIrql();
		KeLowerIrql(PASSIVE_LEVEL);
		KdPrint((DRIVER_PREFIX "Protected value %ws\\%ws\n", regItem.KeyPath, regItem.ValueName));
		KeRaiseIrql(prevIrql, &prevIrql);
		status = STATUS_ACCESS_DENIED;
	}

	CmCallbackReleaseKeyObjectIDEx(regPath);
	return status;
}

NTSTATUS RegNtPostEnumerateKeyHandler(REG_POST_OPERATION_INFORMATION* info) {
	HANDLE key;
	PVOID tempKeyInformation;
	REG_ENUMERATE_KEY_INFORMATION* preInfo;
	PCUNICODE_STRING regPath;
	ULONG resultLength;
	RegItem item;
	UNICODE_STRING keyName;
	int counter = 0;
	NTSTATUS status = STATUS_SUCCESS;
	bool copyKeyInformationData = true;

	if (!NT_SUCCESS(info->Status)) {
		return STATUS_SUCCESS;
	}

	AutoLock locker(rGlobals.Lock);
	status = CmCallbackGetKeyObjectIDEx(&rGlobals.RegCookie, info->Object, nullptr, &regPath, 0);

	if (!NT_SUCCESS(status))
		return STATUS_SUCCESS;

	// Checking if the registry key contains any protected registry key.
	if (!ContainsProtectedRegKey(*regPath, REG_TYPE_KEY)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}
	RtlInitUnicodeString(&keyName, L"");

	preInfo = (REG_ENUMERATE_KEY_INFORMATION*)info->PreInformation;

	if (!GetNameFromKeyEnumPreInfo(preInfo->KeyInformationClass, preInfo->KeyInformation, &keyName)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}
	keyName.Buffer[keyName.Length / sizeof(WCHAR)] = L'\0';

	// Rebuilding the KeyInformation without the hidden keys.
	status = ObOpenObjectByPointerWithTag(info->Object, OBJ_KERNEL_HANDLE, NULL, KEY_ALL_ACCESS, *CmKeyObjectType, KernelMode, DRIVER_TAG, &key);

	if (!NT_SUCCESS(status)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}

	tempKeyInformation = (LPWSTR)ExAllocatePoolWithTag(PagedPool, preInfo->Length, DRIVER_TAG);

	if (tempKeyInformation) {
		item.Type = REG_TYPE_KEY;
		wcsncpy_s(item.KeyPath, regPath->Buffer, regPath->Length / sizeof(WCHAR));

		// To address the situtation of finding several protected keys, need to do a while until found an unprotected key.
		while (copyKeyInformationData) {
			status = ZwEnumerateKey(key, preInfo->Index + counter, preInfo->KeyInformationClass, tempKeyInformation, preInfo->Length, &resultLength);

			if (!NT_SUCCESS(status)) {
				copyKeyInformationData = false;
				continue;
			}

			if (!GetNameFromKeyEnumPreInfo(preInfo->KeyInformationClass, tempKeyInformation, &keyName)) {
				copyKeyInformationData = false;
				continue;
			}
			keyName.Buffer[keyName.Length / sizeof(WCHAR)] = L'\0';

			// Concatenating the key path and name to check against FindRegItem.
			wcscat_s(item.KeyPath, L"\\");
			wcscat_s(item.KeyPath, keyName.Buffer);

			if (!FindRegItem(item)) {
				*preInfo->ResultLength = resultLength;

				__try {
					RtlCopyMemory(preInfo->KeyInformation, tempKeyInformation, resultLength);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {}

				copyKeyInformationData = false;
			}
			else {
				counter++;
				auto prevIrql = KeGetCurrentIrql();
				KeLowerIrql(PASSIVE_LEVEL);
				KdPrint((DRIVER_PREFIX "Hid registry key %ws\n", item.KeyPath));
				KeRaiseIrql(prevIrql, &prevIrql);
			}

			// To avoid concatenating bad data.
			item.KeyPath[0] = L'\0';
			wcsncpy_s(item.KeyPath, regPath->Buffer, regPath->Length / sizeof(WCHAR));
		}

		ExFreePoolWithTag(tempKeyInformation, DRIVER_TAG);
	}
	else
		status = STATUS_SUCCESS;

	info->ReturnStatus = status;
	ZwClose(key);
	CmCallbackReleaseKeyObjectIDEx(regPath);

	return STATUS_SUCCESS;
}

NTSTATUS RegNtPostEnumerateValueKeyHandler(REG_POST_OPERATION_INFORMATION* info) {
	HANDLE key;
	PVOID tempValueInformation;
	REG_ENUMERATE_VALUE_KEY_INFORMATION* preInfo;
	PCUNICODE_STRING regPath;
	UNICODE_STRING valueName;
	ULONG resultLength;
	RegItem item;
	NTSTATUS status = STATUS_SUCCESS;
	bool copyKeyInformationData = true;
	int counter = 0;

	if (!NT_SUCCESS(info->Status)) {
		return STATUS_SUCCESS;
	}

	AutoLock locker(rGlobals.Lock);
	status = CmCallbackGetKeyObjectIDEx(&rGlobals.RegCookie, info->Object, nullptr, &regPath, 0);

	if (!NT_SUCCESS(status))
		return STATUS_SUCCESS;

	// Checking if the registry key contains any protected registry value.
	if (!ContainsProtectedRegKey(*regPath, REG_TYPE_VALUE)) {
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

	tempValueInformation = (PVOID)ExAllocatePoolWithTag(PagedPool, preInfo->Length, DRIVER_TAG);

	if (tempValueInformation) {
		item.Type = REG_TYPE_VALUE;
		wcsncpy_s(item.KeyPath, regPath->Buffer, regPath->Length / sizeof(WCHAR));

		// To address the situtation of finding several protected keys, need to do a while until found an unprotected key.
		while (copyKeyInformationData) {
			status = ZwEnumerateValueKey(key, preInfo->Index + counter, preInfo->KeyValueInformationClass, tempValueInformation, preInfo->Length, &resultLength);

			if (!NT_SUCCESS(status)) {
				copyKeyInformationData = false;
				continue;
			}

			if (!GetNameFromValueEnumPreInfo(preInfo->KeyValueInformationClass, preInfo->KeyValueInformation, &valueName)) {
				copyKeyInformationData = false;
			}
			valueName.Buffer[valueName.Length / sizeof(WCHAR)] = L'\0';
			item.ValueName[0] = L'\0';
			wcsncpy_s(item.ValueName, valueName.Buffer, valueName.Length / sizeof(WCHAR));

			if (!FindRegItem(item)) {
				*preInfo->ResultLength = resultLength;

				// Adding the try & except to be sure, copying memory shouldn't cause a problem.
				__try {
					RtlCopyMemory(preInfo->KeyValueInformation, tempValueInformation, resultLength);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {}

				copyKeyInformationData = false;
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

		ExFreePoolWithTag(tempValueInformation, DRIVER_TAG);
	}
	else
		status = STATUS_SUCCESS;

	info->ReturnStatus = status;
	ZwClose(key);
	CmCallbackReleaseKeyObjectIDEx(regPath);

	return STATUS_SUCCESS;
}

bool GetNameFromValueEnumPreInfo(KEY_VALUE_INFORMATION_CLASS infoClass, PVOID information, PUNICODE_STRING valueName) {
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

bool GetNameFromKeyEnumPreInfo(KEY_INFORMATION_CLASS infoClass, PVOID information, PUNICODE_STRING keyName) {
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

bool FindRegItem(RegItem& item) {
	if (item.Type == REG_TYPE_KEY) {
		for (int i = 0; i < rGlobals.Keys.KeysCount; i++)
			if (_wcsnicmp(rGlobals.Keys.KeysPath[i], item.KeyPath, wcslen(rGlobals.Keys.KeysPath[i])) == 0)
				return true;
	}
	else if (item.Type == REG_TYPE_VALUE) {
		for (int i = 0; i < rGlobals.Values.ValuesCount; i++)
			if (_wcsnicmp(rGlobals.Values.ValuesPath[i], item.KeyPath, wcslen(rGlobals.Values.ValuesPath[i])) == 0 &&
				_wcsnicmp(rGlobals.Values.ValuesName[i], item.ValueName, wcslen(rGlobals.Values.ValuesName[i])) == 0)
				return true;
	}

	return false;
}

bool ContainsProtectedRegKey(UNICODE_STRING regKey, int type) {
	if (type == REG_TYPE_KEY) {
		for (int i = 0; i < rGlobals.Keys.KeysCount; i++) {
			if ((regKey.Length / sizeof(WCHAR)) <= wcslen(rGlobals.Keys.KeysPath[i]) && _wcsnicmp(rGlobals.Keys.KeysPath[i], regKey.Buffer, regKey.Length / sizeof(WCHAR)) == 0)
				return true;
		}
	}
	else if (type == REG_TYPE_VALUE) {
		for (int i = 0; i < rGlobals.Values.ValuesCount; i++) {
			if ((regKey.Length / sizeof(WCHAR)) <= wcslen(rGlobals.Values.ValuesPath[i]) && _wcsnicmp(rGlobals.Values.ValuesPath[i], regKey.Buffer, regKey.Length / sizeof(WCHAR)) == 0)
				return true;
		}
	}
	return false;
}

bool AddRegItem(RegItem& item) {
	if (item.Type == REG_TYPE_KEY) {
		for (int i = 0; i < MAX_REG_ITEMS; i++)
			if (rGlobals.Keys.KeysPath[i] == nullptr) {
				auto len = (wcslen(item.KeyPath) + 1) * sizeof(WCHAR);
				auto buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, len, DRIVER_TAG);

				// Not enough resources.
				if (!buffer) {
					KdPrint((DRIVER_PREFIX "Not enough resources\n"));
					break;
				}

				wcscpy_s(buffer, len / sizeof(WCHAR), item.KeyPath);
				rGlobals.Keys.KeysPath[i] = buffer;
				rGlobals.Keys.KeysCount++;
				return true;
			}
	}
	else if (item.Type == REG_TYPE_VALUE) {
		for (int i = 0; i < MAX_REG_ITEMS; i++) {
			if (rGlobals.Values.ValuesPath[i] == nullptr) {
				auto keyLen = (wcslen(item.KeyPath) + 1) * sizeof(WCHAR);
				auto keyPath = (WCHAR*)ExAllocatePoolWithTag(PagedPool, keyLen, DRIVER_TAG);

				// Not enough resources.
				if (!keyPath) {
					break;
				}

				auto valueNameLen = (wcslen(item.ValueName) + 1) * sizeof(WCHAR);
				auto valueName = (WCHAR*)ExAllocatePoolWithTag(PagedPool, valueNameLen, DRIVER_TAG);

				if (!valueName) {
					ExFreePoolWithTag(keyPath, DRIVER_TAG);
					break;
				}

				wcscpy_s(keyPath, keyLen / sizeof(WCHAR), item.KeyPath);
				wcscpy_s(valueName, valueNameLen / sizeof(WCHAR), item.ValueName);
				rGlobals.Values.ValuesPath[i] = keyPath;
				rGlobals.Values.ValuesName[i] = valueName;
				rGlobals.Values.ValuesCount++;
				return true;
			}
		}
	}
	return false;
}

bool RemoveRegItem(RegItem& item) {
	if (item.Type == REG_TYPE_KEY) {
		for (int i = 0; i < rGlobals.Keys.KeysCount; i++) {

			if (_wcsicmp(rGlobals.Keys.KeysPath[i], item.KeyPath) == 0) {
				ExFreePoolWithTag(rGlobals.Keys.KeysPath[i], DRIVER_TAG);
				rGlobals.Keys.KeysPath[i] = nullptr;
				rGlobals.Keys.KeysCount--;
				return true;
			}
		}
	}
	else if (item.Type == REG_TYPE_VALUE) {
		for (int i = 0; i < rGlobals.Values.ValuesCount; i++)
			if (_wcsicmp(rGlobals.Values.ValuesPath[i], item.KeyPath) == 0 &&
				_wcsicmp(rGlobals.Values.ValuesName[i], item.ValueName) == 0) {
				ExFreePoolWithTag(rGlobals.Values.ValuesPath[i], DRIVER_TAG);
				ExFreePoolWithTag(rGlobals.Values.ValuesName[i], DRIVER_TAG);
				rGlobals.Values.ValuesPath[i] = nullptr;
				rGlobals.Values.ValuesName[i] = nullptr;
				rGlobals.Values.ValuesCount--;
				return true;
			}
	}
	return false;
}

#pragma once
#include "pch.h"

// Definitions.
#define REG_TYPE_PROTECTED_KEY 0
#define REG_TYPE_PROTECTED_VALUE 1
#define REG_TYPE_HIDDEN_KEY 2
#define REG_TYPE_HIDDEN_VALUE 3

// Prototypes.
bool FindRegItem(RegItem& item);
bool ContainsProtectedRegKey(UNICODE_STRING regKey, int type);
bool AddRegItem(RegItem& item);
bool RemoveRegItem(RegItem& item);
bool GetNameFromKeyEnumPreInfo(KEY_INFORMATION_CLASS infoClass, PVOID information, PUNICODE_STRING keyName);
bool GetNameFromValueEnumPreInfo(KEY_VALUE_INFORMATION_CLASS infoClass, PVOID information, PUNICODE_STRING keyName);
NTSTATUS RegNtPreDeleteKeyHandler(REG_DELETE_KEY_INFORMATION* info);
NTSTATUS RegNtPreDeleteValueKeyHandler(REG_DELETE_VALUE_KEY_INFORMATION* info);
NTSTATUS RegNtPreQueryKeyHandler(REG_QUERY_KEY_INFORMATION* info);
NTSTATUS RegNtPreQueryValueKeyHandler(REG_QUERY_VALUE_KEY_INFORMATION* info);
NTSTATUS RegNtPreQueryMultipleValueKeyHandler(REG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION* info);
NTSTATUS RegNtPreSetValueKeyHandler(REG_SET_VALUE_KEY_INFORMATION* info);
NTSTATUS RegNtPostEnumerateKeyHandler(REG_POST_OPERATION_INFORMATION* info);
NTSTATUS RegNtPostEnumerateValueKeyHandler(REG_POST_OPERATION_INFORMATION* info);

NTSTATUS OnRegistryNotify(PVOID context, PVOID arg1, PVOID arg2) {
	UNREFERENCED_PARAMETER(context);
	NTSTATUS status = STATUS_SUCCESS;

	switch ((REG_NOTIFY_CLASS)(ULONG_PTR)arg1) {
	case RegNtPreDeleteKey:
		status = RegNtPreDeleteKeyHandler(static_cast<REG_DELETE_KEY_INFORMATION*>(arg2));
		break;
	case RegNtPreDeleteValueKey:
		status = RegNtPreDeleteValueKeyHandler(static_cast<REG_DELETE_VALUE_KEY_INFORMATION*>(arg2));
		break;
	case RegNtPreQueryKey:
		status = RegNtPreQueryKeyHandler(static_cast<REG_QUERY_KEY_INFORMATION*>(arg2));
		break;
	case RegNtPreQueryValueKey:
		status = RegNtPreQueryValueKeyHandler(static_cast<REG_QUERY_VALUE_KEY_INFORMATION*>(arg2));
		break;
	case RegNtPreQueryMultipleValueKey:
		status = RegNtPreQueryMultipleValueKeyHandler(static_cast<REG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION*>(arg2));
		break;
	case RegNtPreSetValueKey:
		status = RegNtPreSetValueKeyHandler(static_cast<REG_SET_VALUE_KEY_INFORMATION*>(arg2));
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
	regItem.Type = REG_TYPE_PROTECTED_KEY;

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
	regItem.Type = REG_TYPE_PROTECTED_VALUE;

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

NTSTATUS RegNtPreQueryKeyHandler(REG_QUERY_KEY_INFORMATION* info) {
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
	regItem.Type = REG_TYPE_HIDDEN_KEY;

	if (FindRegItem(regItem)) {
		auto prevIrql = KeGetCurrentIrql();
		KeLowerIrql(PASSIVE_LEVEL);
		KdPrint((DRIVER_PREFIX "Hid key from query %ws\n", regItem.KeyPath));
		KeRaiseIrql(prevIrql, &prevIrql);
		status = STATUS_NOT_FOUND;
	}

	CmCallbackReleaseKeyObjectIDEx(regPath);
	return status;
}

NTSTATUS RegNtPreQueryValueKeyHandler(REG_QUERY_VALUE_KEY_INFORMATION* info) {
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
	regItem.Type = REG_TYPE_HIDDEN_VALUE;

	if (FindRegItem(regItem)) {
		auto prevIrql = KeGetCurrentIrql();
		KeLowerIrql(PASSIVE_LEVEL);
		KdPrint((DRIVER_PREFIX "Hid value from query %ws\\%ws\n", regItem.KeyPath, regItem.ValueName));
		KeRaiseIrql(prevIrql, &prevIrql);
		status = STATUS_NOT_FOUND;
	}

	CmCallbackReleaseKeyObjectIDEx(regPath);
	return status;
}

NTSTATUS RegNtPreQueryMultipleValueKeyHandler(REG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION* info) {
	ULONG index;
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

	regItem.Type = REG_TYPE_HIDDEN_VALUE;
	wcsncpy_s(regItem.KeyPath, regPath->Buffer, regPath->Length / sizeof(WCHAR));

	for (index = 0; index < info->EntryCount; index++) {
		wcsncpy_s(regItem.ValueName, info->ValueEntries[index].ValueName->Buffer, info->ValueEntries[index].ValueName->Length / sizeof(WCHAR));

		if (FindRegItem(regItem)) {
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

NTSTATUS RegNtPreSetValueKeyHandler(REG_SET_VALUE_KEY_INFORMATION* info) {
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
	regItem.Type = REG_TYPE_PROTECTED_VALUE;

	if (FindRegItem(regItem)) {
		auto prevIrql = KeGetCurrentIrql();
		KeLowerIrql(PASSIVE_LEVEL);
		KdPrint((DRIVER_PREFIX "Blocked setting value %ws\\%ws\n", regItem.KeyPath, regItem.ValueName));
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
	if (!ContainsProtectedRegKey(*regPath, REG_TYPE_HIDDEN_KEY)) {
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

	tempKeyInformation = (LPWSTR)ExAllocatePoolWithTag(PagedPool, preInfo->Length, DRIVER_TAG);

	if (tempKeyInformation) {
		item.Type = REG_TYPE_HIDDEN_KEY;
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
			keyName.Buffer[keyName.MaximumLength / sizeof(WCHAR)] = L'\0';

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
	if (!ContainsProtectedRegKey(*regPath, REG_TYPE_HIDDEN_VALUE)) {
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
		item.Type = REG_TYPE_HIDDEN_VALUE;
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
	if (item.Type == REG_TYPE_PROTECTED_KEY) {
		for (int i = 0; i < rGlobals.ProtectedItems.Keys.KeysCount; i++)
			if (_wcsnicmp(rGlobals.ProtectedItems.Keys.KeysPath[i], item.KeyPath, wcslen(rGlobals.ProtectedItems.Keys.KeysPath[i])) == 0)
				return true;
	}
	else if (item.Type == REG_TYPE_HIDDEN_KEY) {
		for (int i = 0; i < rGlobals.HiddenItems.Keys.KeysCount; i++)
			if (_wcsnicmp(rGlobals.HiddenItems.Keys.KeysPath[i], item.KeyPath, wcslen(rGlobals.HiddenItems.Keys.KeysPath[i])) == 0)
				return true;
	}
	else if (item.Type == REG_TYPE_PROTECTED_VALUE) {
		for (int i = 0; i < rGlobals.ProtectedItems.Values.ValuesCount; i++)
			if (_wcsnicmp(rGlobals.ProtectedItems.Values.ValuesPath[i], item.KeyPath, wcslen(rGlobals.ProtectedItems.Values.ValuesPath[i])) == 0 &&
				_wcsnicmp(rGlobals.ProtectedItems.Values.ValuesName[i], item.ValueName, wcslen(rGlobals.ProtectedItems.Values.ValuesName[i])) == 0)
				return true;
	}
	else if (item.Type == REG_TYPE_HIDDEN_VALUE) {
		for (int i = 0; i < rGlobals.HiddenItems.Values.ValuesCount; i++)
			if (_wcsnicmp(rGlobals.HiddenItems.Values.ValuesPath[i], item.KeyPath, wcslen(rGlobals.HiddenItems.Values.ValuesPath[i])) == 0 &&
				_wcsnicmp(rGlobals.HiddenItems.Values.ValuesName[i], item.ValueName, wcslen(rGlobals.HiddenItems.Values.ValuesName[i])) == 0)
				return true;
	}

	return false;
}

bool ContainsProtectedRegKey(UNICODE_STRING regKey, int type) {
	if (type == REG_TYPE_PROTECTED_KEY) {
		for (int i = 0; i < rGlobals.ProtectedItems.Keys.KeysCount; i++) {
			if ((regKey.Length / sizeof(WCHAR)) <= wcslen(rGlobals.ProtectedItems.Keys.KeysPath[i]) && _wcsnicmp(rGlobals.ProtectedItems.Keys.KeysPath[i], regKey.Buffer, regKey.Length / sizeof(WCHAR)) == 0)
				return true;
		}
	}
	else if (type == REG_TYPE_HIDDEN_KEY) {
		for (int i = 0; i < rGlobals.HiddenItems.Keys.KeysCount; i++) {
			if ((regKey.Length / sizeof(WCHAR)) <= wcslen(rGlobals.HiddenItems.Keys.KeysPath[i]) && _wcsnicmp(rGlobals.HiddenItems.Keys.KeysPath[i], regKey.Buffer, regKey.Length / sizeof(WCHAR)) == 0)
				return true;
		}
	}
	else if (type == REG_TYPE_PROTECTED_VALUE) {
		for (int i = 0; i < rGlobals.ProtectedItems.Values.ValuesCount; i++) {
			if ((regKey.Length / sizeof(WCHAR)) <= wcslen(rGlobals.ProtectedItems.Values.ValuesPath[i]) && _wcsnicmp(rGlobals.ProtectedItems.Values.ValuesPath[i], regKey.Buffer, regKey.Length / sizeof(WCHAR)) == 0)
				return true;
		}
	}
	else if (type == REG_TYPE_HIDDEN_VALUE) {
		for (int i = 0; i < rGlobals.HiddenItems.Values.ValuesCount; i++) {
			if ((regKey.Length / sizeof(WCHAR)) <= wcslen(rGlobals.HiddenItems.Values.ValuesPath[i]) && _wcsnicmp(rGlobals.HiddenItems.Values.ValuesPath[i], regKey.Buffer, regKey.Length / sizeof(WCHAR)) == 0)
				return true;
		}
	}

	return false;
}

bool AddRegItem(RegItem& item) {
	if (item.Type == REG_TYPE_PROTECTED_KEY) {
		for (int i = 0; i < MAX_REG_ITEMS; i++)
			if (rGlobals.ProtectedItems.Keys.KeysPath[i] == nullptr) {
				auto len = (wcslen(item.KeyPath) + 1) * sizeof(WCHAR);
				auto buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, len, DRIVER_TAG);

				// Not enough resources.
				if (!buffer) {
					KdPrint((DRIVER_PREFIX "Not enough resources\n"));
					break;
				}

				wcscpy_s(buffer, len / sizeof(WCHAR), item.KeyPath);
				rGlobals.ProtectedItems.Keys.KeysPath[i] = buffer;
				rGlobals.ProtectedItems.Keys.KeysCount++;
				return true;
			}
	}
	else if (item.Type == REG_TYPE_HIDDEN_KEY) {
		for (int i = 0; i < MAX_REG_ITEMS; i++)
			if (rGlobals.HiddenItems.Keys.KeysPath[i] == nullptr) {
				auto len = (wcslen(item.KeyPath) + 1) * sizeof(WCHAR);
				auto buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, len, DRIVER_TAG);

				// Not enough resources.
				if (!buffer) {
					KdPrint((DRIVER_PREFIX "Not enough resources\n"));
					break;
				}

				wcscpy_s(buffer, len / sizeof(WCHAR), item.KeyPath);
				rGlobals.HiddenItems.Keys.KeysPath[i] = buffer;
				rGlobals.HiddenItems.Keys.KeysCount++;
				return true;
			}
	}
	else if (item.Type == REG_TYPE_PROTECTED_VALUE) {
		for (int i = 0; i < MAX_REG_ITEMS; i++) {
			if (rGlobals.ProtectedItems.Values.ValuesPath[i] == nullptr) {
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
				rGlobals.ProtectedItems.Values.ValuesPath[i] = keyPath;
				rGlobals.ProtectedItems.Values.ValuesName[i] = valueName;
				rGlobals.ProtectedItems.Values.ValuesCount++;
				return true;
			}
		}
	}

	else if (item.Type == REG_TYPE_HIDDEN_VALUE) {
		for (int i = 0; i < MAX_REG_ITEMS; i++) {
			if (rGlobals.HiddenItems.Values.ValuesPath[i] == nullptr) {
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
				rGlobals.HiddenItems.Values.ValuesPath[i] = keyPath;
				rGlobals.HiddenItems.Values.ValuesName[i] = valueName;
				rGlobals.HiddenItems.Values.ValuesCount++;
				return true;
			}
		}
	}

	return false;
}

bool RemoveRegItem(RegItem& item) {
	if (item.Type == REG_TYPE_PROTECTED_KEY) {
		for (int i = 0; i < rGlobals.ProtectedItems.Keys.KeysCount; i++) {

			if (_wcsicmp(rGlobals.ProtectedItems.Keys.KeysPath[i], item.KeyPath) == 0) {
				ExFreePoolWithTag(rGlobals.ProtectedItems.Keys.KeysPath[i], DRIVER_TAG);
				rGlobals.ProtectedItems.Keys.KeysPath[i] = nullptr;
				rGlobals.ProtectedItems.Keys.KeysCount--;
				return true;
			}
		}
	}
	else if (item.Type == REG_TYPE_HIDDEN_KEY) {
		for (int i = 0; i < rGlobals.HiddenItems.Keys.KeysCount; i++) {

			if (_wcsicmp(rGlobals.HiddenItems.Keys.KeysPath[i], item.KeyPath) == 0) {
				ExFreePoolWithTag(rGlobals.HiddenItems.Keys.KeysPath[i], DRIVER_TAG);
				rGlobals.HiddenItems.Keys.KeysPath[i] = nullptr;
				rGlobals.HiddenItems.Keys.KeysCount--;
				return true;
			}
		}
	}
	else if (item.Type == REG_TYPE_PROTECTED_VALUE) {
		for (int i = 0; i < rGlobals.ProtectedItems.Values.ValuesCount; i++)
			if (_wcsicmp(rGlobals.ProtectedItems.Values.ValuesPath[i], item.KeyPath) == 0 &&
				_wcsicmp(rGlobals.ProtectedItems.Values.ValuesName[i], item.ValueName) == 0) {
				ExFreePoolWithTag(rGlobals.ProtectedItems.Values.ValuesPath[i], DRIVER_TAG);
				ExFreePoolWithTag(rGlobals.ProtectedItems.Values.ValuesName[i], DRIVER_TAG);
				rGlobals.ProtectedItems.Values.ValuesPath[i] = nullptr;
				rGlobals.ProtectedItems.Values.ValuesName[i] = nullptr;
				rGlobals.ProtectedItems.Values.ValuesCount--;
				return true;
			}
	}
	else if (item.Type == REG_TYPE_HIDDEN_VALUE) {
		for (int i = 0; i < rGlobals.HiddenItems.Values.ValuesCount; i++)
			if (_wcsicmp(rGlobals.HiddenItems.Values.ValuesPath[i], item.KeyPath) == 0 &&
				_wcsicmp(rGlobals.HiddenItems.Values.ValuesName[i], item.ValueName) == 0) {
				ExFreePoolWithTag(rGlobals.HiddenItems.Values.ValuesPath[i], DRIVER_TAG);
				ExFreePoolWithTag(rGlobals.HiddenItems.Values.ValuesName[i], DRIVER_TAG);
				rGlobals.HiddenItems.Values.ValuesPath[i] = nullptr;
				rGlobals.HiddenItems.Values.ValuesName[i] = nullptr;
				rGlobals.HiddenItems.Values.ValuesCount--;
				return true;
			}
	}
	return false;
}

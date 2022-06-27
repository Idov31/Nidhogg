#pragma once
#include "pch.h"

// Definitions.
#define REG_TYPE_KEY 0
#define REG_TYPE_VALUE 1

// Prototypes.
bool FindRegItem(RegItem& item);
bool ContainsProtectedRegKey(PCUNICODE_STRING regKey, int type);
bool AddRegItem(RegItem& item);
bool RemoveRegItem(RegItem& item);
bool GetNameFromKeyEnumPreInfo(KEY_INFORMATION_CLASS infoClass, PVOID information, PUNICODE_STRING keyName);
bool GetNameFromValueEnumPreInfo(KEY_VALUE_INFORMATION_CLASS infoClass, PVOID information, PUNICODE_STRING keyName);
NTSTATUS RegNtPreDeleteKeyHandler(REG_DELETE_KEY_INFORMATION* info);
NTSTATUS RegNtPreDeleteValueKeyHandler(REG_DELETE_VALUE_KEY_INFORMATION* info);
NTSTATUS RegNtPostEnumerateKeyHandler(PREG_POST_OPERATION_INFORMATION info);
NTSTATUS RegNtPostEnumerateValueKeyHandler(PREG_POST_OPERATION_INFORMATION info);

NTSTATUS OnRegistryNotify(PVOID context, PVOID arg1, PVOID arg2) {
	UNREFERENCED_PARAMETER(context);
	NTSTATUS status = STATUS_SUCCESS;

	// Need to also add: PreQueryValue, PreQueryMultipleValue, SetValueKey
	switch ((REG_NOTIFY_CLASS)(ULONG_PTR)arg1) {
	case RegNtPreDeleteKey:
		status = RegNtPreDeleteKeyHandler(static_cast<REG_DELETE_KEY_INFORMATION*>(arg2));
		break;
		/*case RegNtPreDeleteValueKey:
			status = RegNtPreDeleteValueKeyHandler(static_cast<REG_DELETE_VALUE_KEY_INFORMATION*>(arg2));
			break;*/
		/*case RegNtPostEnumerateKey:
			status = RegNtPostEnumerateKeyHandler((PREG_POST_OPERATION_INFORMATION)regInfo);
			break;
		case RegNtPostEnumerateValueKey:
			status = RegNtPostEnumerateValueKeyHandler((PREG_POST_OPERATION_INFORMATION)regInfo);
			break;*/
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
		KdPrint((DRIVER_PREFIX "Protected: %ws\n", regItem.KeyPath));
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
		KdPrint((DRIVER_PREFIX "protected from deletion! (value)\n"));
		status = STATUS_ACCESS_DENIED;
	}

	CmCallbackReleaseKeyObjectIDEx(regPath);
	return status;
}

NTSTATUS RegNtPostEnumerateKeyHandler(PREG_POST_OPERATION_INFORMATION info) {
	HANDLE key;
	PVOID tempKeyInformation;
	PREG_ENUMERATE_KEY_INFORMATION preInfo;
	PCUNICODE_STRING regPath;
	UNICODE_STRING keyName;
	ULONG resultLength;
	RegItem item;
	NTSTATUS status = STATUS_SUCCESS;
	bool copyKeyInformationData = true;
	int counter = 1;

	if (!NT_SUCCESS(info->Status)) {
		return STATUS_SUCCESS;
	}

	AutoLock locker(rGlobals.Lock);
	status = CmCallbackGetKeyObjectIDEx(&rGlobals.RegCookie, info->Object, nullptr, &regPath, 0);

	if (!NT_SUCCESS(status))
		return STATUS_SUCCESS;

	// Checking if the registry key contains any protected registry key.
	if (!ContainsProtectedRegKey(regPath, REG_TYPE_KEY)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}

	preInfo = (PREG_ENUMERATE_KEY_INFORMATION)info->PreInformation;

	if (!GetNameFromKeyEnumPreInfo(preInfo->KeyInformationClass, preInfo->KeyInformation, &keyName)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}

	// Rebuilding the KeyInformation without the hidden keys.
	status = ObOpenObjectByPointerWithTag(info->Object, OBJ_KERNEL_HANDLE, NULL, KEY_ALL_ACCESS, *CmKeyObjectType, KernelMode, DRIVER_TAG, &key);

	if (!NT_SUCCESS(status)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}

	tempKeyInformation = (PVOID)ExAllocatePoolWithTag(PagedPool, preInfo->Length, DRIVER_TAG);

	if (tempKeyInformation) {
		// item = (RegItem*)ExAllocatePoolWithTag(PagedPool, sizeof(RegItem), DRIVER_TAG);

		//if (item) {
		//	item->Type = REG_TYPE_KEY;

		//	// To address the situtation of finding several protected keys, need to do a while until found an unprotected key.
		//	while (copyKeyInformationData) {
		//		wcscpy_s(item->KeyPath, wcslen(keyName.Buffer) + 1, keyName.Buffer);
		//		status = ZwEnumerateKey(key, preInfo->Index + counter, preInfo->KeyInformationClass, tempKeyInformation, preInfo->Length, &resultLength);

		//		if (!NT_SUCCESS(status)) {
		//			copyKeyInformationData = false;
		//			continue;
		//		}

		//		if (!FindRegItem(item)) {
		//			*preInfo->ResultLength = resultLength;

		//			// Adding the try & except to be sure, copying memory shouldn't cause a problem.
		//			__try {
		//				RtlCopyMemory(preInfo->KeyInformation, tempKeyInformation, resultLength);
		//			}
		//			__except (EXCEPTION_EXECUTE_HANDLER) {}

		//			copyKeyInformationData = false;
		//			continue;
		//		}

		//		if (!GetNameFromKeyEnumPreInfo(preInfo->KeyInformationClass, tempKeyInformation, &keyName)) {
		//			copyKeyInformationData = false;
		//		}
		//	}

		//	ExFreePoolWithTag(item, DRIVER_TAG);
		//	item = nullptr;
		//}

		item.Type = REG_TYPE_KEY;

		// To address the situtation of finding several protected keys, need to do a while until found an unprotected key.
		while (copyKeyInformationData) {
			// wcscpy_s(item.KeyPath, wcslen(keyName.Buffer) + 1, keyName.Buffer);
			wcsncpy_s(item.KeyPath, keyName.Buffer, wcslen(keyName.Buffer));
			status = ZwEnumerateKey(key, preInfo->Index + counter, preInfo->KeyInformationClass, tempKeyInformation, preInfo->Length, &resultLength);

			if (!NT_SUCCESS(status)) {
				copyKeyInformationData = false;
				continue;
			}

			if (!FindRegItem(item)) {
				*preInfo->ResultLength = resultLength;

				// Adding the try & except to be sure, copying memory shouldn't cause a problem.
				__try {
					RtlCopyMemory(preInfo->KeyInformation, tempKeyInformation, resultLength);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {}

				copyKeyInformationData = false;
				continue;
			}

			if (!GetNameFromKeyEnumPreInfo(preInfo->KeyInformationClass, tempKeyInformation, &keyName)) {
				copyKeyInformationData = false;
			}
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

NTSTATUS RegNtPostEnumerateValueKeyHandler(PREG_POST_OPERATION_INFORMATION info) {
	HANDLE key;
	PVOID tempValueInformation;
	PREG_ENUMERATE_VALUE_KEY_INFORMATION preInfo;
	PCUNICODE_STRING regPath;
	UNICODE_STRING valueName;
	ULONG resultLength;
	RegItem item;
	NTSTATUS status = STATUS_SUCCESS;
	bool copyKeyInformationData = true;
	int counter = 1;

	if (!NT_SUCCESS(info->Status)) {
		return STATUS_SUCCESS;
	}

	AutoLock locker(rGlobals.Lock);
	status = CmCallbackGetKeyObjectIDEx(&rGlobals.RegCookie, info->Object, nullptr, &regPath, 0);

	if (!NT_SUCCESS(status))
		return STATUS_SUCCESS;

	// Checking if the registry key contains any protected registry key.
	if (!ContainsProtectedRegKey(regPath, REG_TYPE_KEY)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}

	preInfo = (PREG_ENUMERATE_VALUE_KEY_INFORMATION)info->PreInformation;

	if (!GetNameFromValueEnumPreInfo(preInfo->KeyValueInformationClass, preInfo->KeyValueInformation, &valueName)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}

	// Rebuilding the KeyInformation without the hidden keys.
	status = ObOpenObjectByPointerWithTag(info->Object, OBJ_KERNEL_HANDLE, NULL, KEY_ALL_ACCESS, *CmKeyObjectType, KernelMode, DRIVER_TAG, &key);

	if (!NT_SUCCESS(status)) {
		CmCallbackReleaseKeyObjectIDEx(regPath);
		return STATUS_SUCCESS;
	}

	tempValueInformation = (PVOID)ExAllocatePoolWithTag(PagedPool, preInfo->Length, DRIVER_TAG);

	if (tempValueInformation) {
		//item = (RegItem*)ExAllocatePoolWithTag(PagedPool, sizeof(RegItem), DRIVER_TAG);

		//if (item) {
		//	item->Type = REG_TYPE_VALUE;

		//	// To address the situtation of finding several protected keys, need to do a while until found an unprotected key.
		//	while (copyKeyInformationData) {
		//		wcscpy_s(item->KeyPath, wcslen(regPath->Buffer) + 1, regPath->Buffer);
		//		wcscpy_s(item->ValueName, wcslen(valueName.Buffer) + 1, valueName.Buffer);
		//		status = ZwEnumerateValueKey(key, preInfo->Index + counter, preInfo->KeyValueInformationClass, tempValueInformation, preInfo->Length, &resultLength);

		//		if (!NT_SUCCESS(status)) {
		//			copyKeyInformationData = false;
		//			continue;
		//		}

		//		if (!FindRegItem(item)) {
		//			*preInfo->ResultLength = resultLength;

		//			// Adding the try & except to be sure, copying memory shouldn't cause a problem.
		//			__try {
		//				RtlCopyMemory(preInfo->KeyValueInformation, tempValueInformation, resultLength);
		//			}
		//			__except (EXCEPTION_EXECUTE_HANDLER) {}

		//			copyKeyInformationData = false;
		//			continue;
		//		}

		//		if (!GetNameFromValueEnumPreInfo(preInfo->KeyValueInformationClass, preInfo->KeyValueInformation, &valueName)) {
		//			copyKeyInformationData = false;
		//		}
		//	}
		//	ExFreePoolWithTag(item, DRIVER_TAG);
		//	item = nullptr;
		//}

		item.Type = REG_TYPE_VALUE;

		// To address the situtation of finding several protected keys, need to do a while until found an unprotected key.
		while (copyKeyInformationData) {
			/*wcscpy_s(item->KeyPath, wcslen(regPath->Buffer) + 1, regPath->Buffer);
			wcscpy_s(item->ValueName, wcslen(valueName.Buffer) + 1, valueName.Buffer);*/
			wcsncpy_s(item.KeyPath, regPath->Buffer, regPath->Length / sizeof(WCHAR) - 1);
			wcsncpy_s(item.KeyPath, valueName.Buffer, wcslen(valueName.Buffer));
			status = ZwEnumerateValueKey(key, preInfo->Index + counter, preInfo->KeyValueInformationClass, tempValueInformation, preInfo->Length, &resultLength);

			if (!NT_SUCCESS(status)) {
				copyKeyInformationData = false;
				continue;
			}

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

			if (!GetNameFromValueEnumPreInfo(preInfo->KeyValueInformationClass, preInfo->KeyValueInformation, &valueName)) {
				copyKeyInformationData = false;
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
		PKEY_VALUE_BASIC_INFORMATION valueInfo = (PKEY_VALUE_BASIC_INFORMATION)information;
		valueName->Buffer = valueInfo->Name;
		valueName->Length = (USHORT)valueInfo->NameLength;
		valueName->MaximumLength = (USHORT)valueInfo->NameLength;
		break;
	}
	case KeyValueFullInformation:
	case KeyValueFullInformationAlign64:
	{
		PKEY_VALUE_FULL_INFORMATION valueInfo = (PKEY_VALUE_FULL_INFORMATION)information;
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
		PKEY_BASIC_INFORMATION basicInfo = (PKEY_BASIC_INFORMATION)information;
		keyName->Buffer = basicInfo->Name;
		keyName->Length = (USHORT)basicInfo->NameLength;
		keyName->MaximumLength = (USHORT)basicInfo->NameLength;
		break;
	}
	case KeyNameInformation:
	{
		PKEY_NAME_INFORMATION nameInfo = (PKEY_NAME_INFORMATION)information;
		keyName->Buffer = nameInfo->Name;
		keyName->Length = (USHORT)nameInfo->NameLength;
		keyName->MaximumLength = (USHORT)nameInfo->NameLength;
		break;
	}
	case KeyNodeInformation:
	{
		PKEY_NODE_INFORMATION nodeInfo = (PKEY_NODE_INFORMATION)information;
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
			if (_wcsicmp(rGlobals.Keys.KeysPath[i], item.KeyPath) == 0)
				return true;
	}
	else if (item.Type == REG_TYPE_VALUE) {
		for (int i = 0; i < rGlobals.Values.ValuesCount; i++)
			if (_wcsicmp(rGlobals.Values.ValuesPath[i], item.KeyPath) == 0 &&
				_wcsicmp(rGlobals.Values.ValuesName[i], item.ValueName) == 0)
				return true;
	}
	return false;
}

bool ContainsProtectedRegKey(PCUNICODE_STRING regKey, int type) {
	if (type == REG_TYPE_KEY) {
		for (int i = 0; i < rGlobals.Keys.KeysCount; i++) {
			if (wcsstr(regKey->Buffer, rGlobals.Keys.KeysPath[i]))
				return true;
		}
	}
	else if (type == REG_TYPE_VALUE) {
		for (int i = 0; i < rGlobals.Values.ValuesCount; i++) {
			if (wcsstr(regKey->Buffer, rGlobals.Values.ValuesPath[i]))
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

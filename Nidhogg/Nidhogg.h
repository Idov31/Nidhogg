#pragma once
#include "pch.h"
#include "WindowsTypes.hpp"
#include "NidhoggUtils.h"
#include "ProcessUtils.hpp"
#include "FileUtils.hpp"
#include "RegistryUtils.hpp"
#include "MemoryUtils.hpp"
#include "AntiAnalysis.hpp"
#include "NidhoggDeviceControl.hpp"

// Definitions.
#define REGISTERED_OB_CALLBACKS 2
#define DRIVER_NAME L"\\Driver\\Nidhogg"
#define DRIVER_DEVICE_NAME L"\\Device\\Nidhogg"
#define DRIVER_SYMBOLIC_LINK L"\\??\\Nidhogg"
#define OB_CALLBACKS_ALTITUDE L"31105.6171"
#define REG_CALLBACK_ALTITUDE L"31122.6172"

// Prototypes.
NTSTATUS NidhoggEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0);
DRIVER_UNLOAD NidhoggUnload;
DRIVER_DISPATCH NidhoggDeviceControl, NidhoggCreateClose;
void ClearAll();
void InitializeFeatures();

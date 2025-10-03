#pragma once
#include "pch.h"
#include "IoctlShared.h"
#include "MemoryHelper.h"
#include "MemoryAllocator.hpp"
#include "ProcessHandler.h"
#include "ThreadHandler.h"
#include "MemoryHandler.h"
#include "FileHandler.h"
#include "RegistryHandler.h"
#include "AntiAnalysisHandler.h"
#include "NetworkHandler.h"
#include "ScriptManager.h"

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS NidhoggCreateClose(_Inout_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS NidhoggDeviceControl(_Inout_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

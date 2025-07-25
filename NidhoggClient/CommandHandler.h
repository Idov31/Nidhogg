#pragma once
#include "pch.h"
#include "NidhoggStructs.h"
#include "NidhoggIoctls.h"
#include "Helper.h"

constexpr DWORD SYSTEM_PID = 4;

class CommandHandler {
protected:
	std::string contextName;
	std::shared_ptr<HANDLE> hNidhogg;

public:
	CommandHandler(_In_ std::string contextName, _In_ std::shared_ptr<HANDLE> hNidhogg) {
		this->contextName = contextName;
		this->hNidhogg = hNidhogg;
	}

	void GetCommand() {
		std::string command = "";

		do {
			std::cout << "[Nidhogg :: " << contextName << "]>> ";
			std::cin >> command;

			if (command.compare("back") == 0)
				break;
			if (command.compare("exit") == 0)
				exit(0);
			HandleCommand(command);
			command = "";
		} while (true);
	};
	virtual void PrintHelp() {};
	virtual void HandleCommand(_In_ std::string command) {};
};

#pragma once
#include "pch.h"
#include "NidhoggStructs.h"
#include "NidhoggIoctls.h"
#include "Helper.h"

class CommandHandler {
protected:
	std::string contextName;
	std::shared_ptr<HANDLE> hNidhogg;

public:
	CommandHandler(_In_ std::string contextName, _In_ std::shared_ptr<HANDLE> hNidhogg) {
		this->contextName = contextName;
		this->hNidhogg = hNidhogg;
	}
	~CommandHandler() {}

	void GetCommand() {
		std::string command = "";

		do {
			std::cout << "[Nidhogg :: " << contextName << "]>> ";
			std::cin >> command;

			if (command.compare("back") == 0)
				break;
			if (command.compare("exit") == 0)
				exit(0); // TODO: Handle exit gracefully
			HandleCommand(command);
			command = "";
		} while (true);
	};

	void GetCommand(_In_ std::string command) {
		if (command.compare("back") == 0 || command.compare("exit") == 0)
			return;
		HandleCommand(command);
	};
	virtual void PrintHelp() {};
	virtual void HandleCommand(_In_ std::string command) {};
};

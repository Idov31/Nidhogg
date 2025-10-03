#pragma once
#include "pch.h"
#include "WindowsTypes.h"
#include "..\Nidhogg\IoctlShared.h"
#include "Helper.h"

struct Test {
	bool Safe;
	std::function<bool(const PVOID& tester, std::string command)> Func;
};

class CommandHandler {
protected:
	std::string contextName;
	std::shared_ptr<HANDLE> hNidhogg;
	std::unordered_map<std::string, Test> tests;

public:
	CommandHandler(_In_ std::string contextName, _In_ std::shared_ptr<HANDLE> hNidhogg) {
		this->contextName = contextName;
		this->hNidhogg = hNidhogg;
	}
	~CommandHandler() {}

	bool GetCommand() {
		std::string command = "";

		do {
			std::cout << termcolor::magenta << "[Nidhogg :: " << contextName << "]>> " << termcolor::reset;
			std::cin >> command;

			if (command.empty() || command.compare("help") == 0) {
				PrintHelp();
				continue;
			}
			else if (command.compare("back") == 0)
				break;
			else if (command.compare("exit") == 0)
				return true;
			HandleCommand(command);
			command = "";
		} while (true);

		return false;
	};

	void GetCommand(_In_ std::string command) {
		if (command.empty() || command.compare("help") == 0) {
			PrintHelp();
			return;
		}
		if (command.starts_with("test") == 0) {
			if (command.compare("test_safe") == 0) {
				if (TestSafe())
					std::cout << termcolor::green << "[+] All safe tests passed!" << termcolor::reset << std::endl;
				else
					std::cout << termcolor::red << "[-] Some safe tests failed!" << termcolor::reset << std::endl;
				return;
			}
			else if (command.compare("test_all") == 0) {
				if (TestAll())
					std::cout << termcolor::green << "[+] All tests passed!" << termcolor::reset << std::endl;
				else
					std::cout << termcolor::red << "[-] Some tests failed!" << termcolor::reset << std::endl;
				return;
			}

			if (command.length() <= 5) {
				std::cout << termcolor::red << "[-] Invalid test command!" << termcolor::reset << std::endl;
				return;
			}
			TestFeature(command.substr(5));
			return;
		}
		if (command.compare("back") == 0 || command.compare("exit") == 0)
			return;
		HandleCommand(command);
	};

	virtual void PrintHelp() {};
	virtual void HandleCommand(_In_ std::string command) {};

	virtual bool TestSafe() { return true; };
	virtual bool TestUnsafe() { return true; };
	virtual bool TestFeature(_In_ std::string featureName) { return true; };

	bool TestAll() {
		return TestSafe() && TestUnsafe();
	}
};

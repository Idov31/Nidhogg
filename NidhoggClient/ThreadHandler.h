#pragma once
#include "pch.h"
#include "CommandHandler.h"

class ThreadHandlerException : public std::runtime_error {
private:
	std::string msg;
public:
	ThreadHandlerException(_In_ const std::string& message)
		: std::runtime_error(message), msg(message) {}
	const char* what() const override {
		return msg.c_str();
	}
};

class ThreadHandler : public CommandHandler {
private:
	bool Protect(_In_ DWORD tid, _In_ bool protect);
	bool Hide(_In_ DWORD tid, _In_ bool hide);
	std::vector<DWORD> ListThreads(_In_ ThreadType type);
	bool ClearThreads(_In_ ThreadType type);
	bool CheckInput(_In_ const std::vector<std::string>& params);

public:
	ThreadHandler(_In_ std::shared_ptr<HANDLE> hNidhogg) : CommandHandler("Thread", hNidhogg) {};

	void PrintHelp() override {
		std::cout << termcolor::bright_magenta << termcolor::underline << "Options:" << termcolor::reset << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "exit - Exit the program" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "back - Go back to the main menu" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "[add | protect] [tid] - Protecting a thread from being killed" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "[remove | unprotect] [tid] - Removing protection from a thread" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "hide [tid] - Hide a thread" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "[unhide | restore] [tid] - Revealing a process after hiding it" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "list [hidden | protected] - Listing the currently hidden or protected threads" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "clear [all | hidden | protected] - Clear all hidden or protected threads" << std::endl;
	}

	void HandleCommand(_In_ std::string command) override;
};

#pragma once
#include "pch.h"
#include "CommandHandler.h"

class FileHandlerException : public std::runtime_error {
private:
	std::string msg;
public:
	FileHandlerException(_In_ const std::string& message)
		: std::runtime_error(message), msg(message) {}
	const char* what() const override {
		return msg.c_str();
	}
};

class FileHandler : public CommandHandler {
private:
	bool Protect(_In_ std::wstring filePath, _In_ bool protect);
	std::vector<std::wstring> ListProtectedFiles();
	bool ClearProtectedFiles();

public:
	FileHandler(_In_ std::shared_ptr<HANDLE> hNidhogg) : CommandHandler("File", hNidhogg) {};

	void PrintHelp() override {
		std::cout << termcolor::bright_magenta << termcolor::underline << "Options:" << termcolor::reset << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "back - Go back to the main menu" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "[add | protect] [file path] - Protecting a file path from being deleted" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "[remove | unprotect] [file path] - Removing protection from a file path from being deleted" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "list - Listing the currently protected files" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "clear - Clear all protected files" << std::endl;
	}

	void HandleCommand(_In_ std::string command) override;
};

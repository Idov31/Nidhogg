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
		std::cout << "Options:" << std::endl;
		std::cout << "back - Go back to the main menu" << std::endl;
		std::cout << "[add | protect] [file path] - Protecting a file path from being deleted" << std::endl;
		std::cout << "[remove | unprotect] [file path] - Removing protection from a file path from being deleted" << std::endl;
		std::cout << "list - Listing the currently protected files" << std::endl;
		std::cout << "clear - Clear all protected files" << std::endl;
	}

	void HandleCommand(_In_ std::string command) override;
};

#pragma once
#include "pch.h"
#include "CommandHandler.h"

class ThreadHandler : protected CommandHandler {
private:
	bool Protect(_In_ DWORD tid, _In_ bool protect);
	bool Hide(_In_ DWORD tid, _In_ bool hide);
	std::vector<DWORD> ListProtectedThreads();
	bool ClearProtectedThreads();
	bool CheckInput(_In_ const std::vector<std::string>& params);

public:
	ThreadHandler(_In_ std::shared_ptr<HANDLE> hNidhogg) : CommandHandler("Thread", hNidhogg) {};

	void PrintHelp() override {
		std::cout << "Options:" << std::endl;
		std::cout << "exit - Exit the program" << std::endl;
		std::cout << "back - Go back to the main menu" << std::endl;
		std::cout << "[add | protect] [pid] - Protecting a thread from being killed" << std::endl;
		std::cout << "[remove | unprotect] [pid] - Removing protection from a thread" << std::endl;
		std::cout << "[hide] [pid] - Hide a process" << std::endl;
		std::cout << "[unhide | restore] [pid] - Revealing a process after hiding it" << std::endl;
		std::cout << "list - Listing the currently protected threads" << std::endl;
		std::cout << "clear - Clear all protected threads" << std::endl;
	}

	void HandleCommand(_In_ std::string command) override;
};

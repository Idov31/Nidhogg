#pragma once
#include "pch.h"
#include "AntiAnalysisHandler.h"
#include "FileHandler.h"
#include "MemoryHandler.h"
#include "NetworkHandler.h"
#include "ProcessHandler.h"
#include "RegistryHandler.h"
#include "ThreadHandler.h"

constexpr wchar_t NIDHOGG_DEVICE_NAME[] = L"\\\\.\\Nidhogg";

class NidhoggInterfaceException : public std::runtime_error {
private:
	std::string msg;
public:
	NidhoggInterfaceException(_In_ const std::string& message)
		: std::runtime_error(message), msg(message) {}
	const char* what() const override {
		return msg.c_str();
	}
};

class NidhoggInterface {
private:
	std::shared_ptr<HANDLE> hNidhogg;
	std::unordered_map<std::string, std::unique_ptr<CommandHandler>> commandHandlers;
	bool IsValidHandle(HANDLE handle) { return handle && handle != INVALID_HANDLE_VALUE; }

public:
	NidhoggInterface();
	~NidhoggInterface();
	void HandleCommands();
	void HandleCommand(_In_ std::string handler, _In_ std::string command);
};


#pragma once
#include "pch.h"

class ProcessHelperException : public std::runtime_error {
private:
	std::string msg;
public:
	ProcessHelperException(_In_ const std::string& message)
		: std::runtime_error(message), msg(message) {}
	const char* what() const override {
		return msg.c_str();
	}
};

DWORD FindPidByName(_In_ const std::string& processName);
DWORD CreateProcessByName(_In_ const std::string& processName);
bool KillProcessByName(_In_ const std::string& processName);

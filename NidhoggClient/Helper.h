#pragma once

#include "pch.h"
#include "SafeMemory.hpp"
#include "Convertor.hpp"
#include "PathHelper.hpp"

constexpr DWORD SYSTEM_PID = 4;

class HelperException : public std::runtime_error
{
    std::string msg;
public:
    HelperException(_In_ const std::string& message)
		: std::runtime_error(message), msg(message) {}
    const char* what() const override
    {
        return msg.c_str();
    }
};

bool EnableColors();
void ToLower(_Inout_ std::string& str);
std::wstring GetCurrentUserSID();
std::vector<std::string> SplitStringBySpace(_In_ const std::string& str);
std::vector<std::wstring> SplitStringBySpaceW(_In_ const std::string& str);
bool IsValidPid(_In_ std::string rawPid);
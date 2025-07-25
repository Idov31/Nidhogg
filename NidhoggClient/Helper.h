#pragma once

#include "pch.h"

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

std::vector<byte> ConvertToVector(_In_ std::wstring rawPatch);
int ConvertToInt(_In_ std::wstring rawString);
std::wstring GetCurrentUserSID();
std::vector<std::string> SplitStringBySpace(_In_ const std::string& str);
std::vector<std::wstring> SplitStringBySpaceW(_In_ const std::string& str);
std::wstring ParsePath(std::wstring path);
void PrintUsage();
#pragma once

#include "pch.h"

class HelperException : public std::runtime_error
{
    std::string msg;
public:
    HelperException(const std::string& message)
		: std::runtime_error(message), msg(message) {}
    const char* what() const override
    {
        return msg.c_str();
    }
};

std::vector<byte> ConvertToVector(std::wstring rawPatch);
int ConvertToInt(std::wstring rawString);
std::wstring GetCurrentUserSID();
void PrintUsage();
#pragma once

#include "pch.h"

constexpr DWORD SYSTEM_PID = 4;
constexpr char WINDOWS_PATH[] = R"(C:\Windows)";
constexpr char NATIVE_WINDOWS_PATH[] = R"(\SystemRoot)";
constexpr char DEFAULT_DRIVE[] = R"(C:\)";
constexpr char NATIVE_DEFAULT_DRIVE[] = R"(\??\C:\)";

template<typename T>
concept TString = std::same_as<T, std::string> || std::same_as<T, std::wstring>;

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

void SafeFree(_Inout_opt_ PVOID ptr);

template<TString String>
std::vector<byte> ConvertToVector(_In_ String rawPatch);
int ConvertToInt(_In_ std::wstring rawString);
std::wstring GetCurrentUserSID();
std::vector<std::string> SplitStringBySpace(_In_ const std::string& str);
std::vector<std::wstring> SplitStringBySpaceW(_In_ const std::string& str);

template<TString String>
bool IsValidPath(_In_ const String& path);

template<TString InputString, TString OutputString>
OutputString ParsePath(_In_ InputString path);
bool IsValidPid(_In_ std::string rawPid);
void PrintUsage();
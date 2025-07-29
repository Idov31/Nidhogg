#pragma once
#include "pch.h"

constexpr char WINDOWS_PATH[] = R"(C:\Windows)";
constexpr char NATIVE_WINDOWS_PATH[] = R"(\SystemRoot)";
constexpr char DEFAULT_DRIVE[] = R"(C:\)";
constexpr char NATIVE_DEFAULT_DRIVE[] = R"(\??\C:\)";

class PathHelperException : public std::runtime_error
{
	std::string msg;
public:
	PathHelperException(_In_ const std::string& message)
		: std::runtime_error(message), msg(message) {}
	const char* what() const override
	{
		return msg.c_str();
	}
};

/*
* Description:
* IsValidPath is responsible for checking if a given path is valid.
*
* Parameters:
* @path [_In_ const string&] -- The path to be checked.
*
* Returns:
* @bool						 -- Whether the path is valid or not.
*/
template<TString String>
inline bool IsValidPath(_In_ const String& path) {
	if (path.length() > MAX_PATH) {
		std::cerr << "Path length exceeds MAX_PATH" << std::endl;
		return false;
	}

	if (!std::filesystem::exists(path)) {
		std::cerr << "Path does not exist" << std::endl;
		return false;
	}
	return true;
}

/*
* Description:
* ParsePath is responsible for parsing a file path and replacing certain parts with predefined strings.
*
* Parameters:
* @path [_In_ InputString] -- The file path to be parsed.
*
* Returns:
* @result [OutputString] -- The parsed file path with certain parts replaced.
*/
template<TString InputString, TString OutputString>
inline OutputString ParsePath(_In_ InputString path) {
	if (!IsValidPath<InputString>(path))
		throw PathHelperException("Invalid path provided");
	OutputString result = OutputString(path.begin(), path.end());

	OutputString windowsPath = OutputString(WINDOWS_PATH, WINDOWS_PATH + strlen(WINDOWS_PATH));
	OutputString nativeWindowsPath = OutputString(NATIVE_WINDOWS_PATH, NATIVE_WINDOWS_PATH + strlen(NATIVE_WINDOWS_PATH));
	OutputString defaultDrive = OutputString(DEFAULT_DRIVE, DEFAULT_DRIVE + strlen(DEFAULT_DRIVE));
	OutputString nativeDefaultDrive = OutputString(NATIVE_DEFAULT_DRIVE, NATIVE_DEFAULT_DRIVE + strlen(NATIVE_DEFAULT_DRIVE));

	auto windowsPos = result.find(windowsPath);

	if (windowsPos != OutputString::npos) {
		result.replace(windowsPos, windowsPath.length(), nativeWindowsPath);
	}
	else {
		auto drivePos = result.find(defaultDrive);

		if (drivePos != OutputString::npos) {
			result.replace(drivePos, defaultDrive.length(), nativeDefaultDrive);
		}
	}
	return result;
}
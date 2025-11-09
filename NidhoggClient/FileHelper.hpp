#pragma once
#include "pch.h"

constexpr char NATIVE_WINDOWS_PATH[] = R"(\SystemRoot)";
constexpr char NT_DRIVE_PREFIX[] = R"(\??\)";
constexpr char SYSTEM_ROOT_ENV[] = "SYSTEMROOT";
constexpr char SYSTEM_DRIVE_ENV[] = "SystemDrive";

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
	bool exists = false;

	if (path.length() == 0 || path.length() > MAX_PATH) {
		std::cerr << "Invalid path length" << std::endl;
		return exists;
	}

	try {
		if (std::filesystem::exists(path))
			exists = true;
	}
	catch (const std::filesystem::filesystem_error& e) {
		if (e.code().value() == ERROR_ACCESS_DENIED) {
			return true;
		}
		std::cerr << "Filesystem error: " << e.what() << std::endl;
		return false;
	}
	return exists;
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
	InputString systemDir;
	InputString systemDrive;
	char* buffer = nullptr;

	if (!IsValidPath<InputString>(path))
		throw PathHelperException("Invalid path provided");
	OutputString result = OutputString(path.begin(), path.end());
	OutputString nativeWindowsPath;

	if constexpr (IsUnicodeString<OutputString>) {
		nativeWindowsPath = OutputString(std::begin(NATIVE_WINDOWS_PATH), std::end(NATIVE_WINDOWS_PATH) - 1);
	}
	else {
		nativeWindowsPath = OutputString(NATIVE_WINDOWS_PATH);
	}

	if (_dupenv_s(&buffer, nullptr, SYSTEM_ROOT_ENV) == 0) {
		if (!buffer || strlen(buffer) == 0) {
			throw PathHelperException("Failed to get SYSTEMROOT environment variable");
		}
		if constexpr (IsUnicodeString<InputString>) {
			size_t len = strlen(buffer);
			systemDir.resize(len);
			mbstowcs_s(nullptr, systemDir.data(), len + 1, buffer, len);
		}
		else {
			systemDir = InputString(buffer);
		}
		SafeFree(buffer);
	}

	if (_dupenv_s(&buffer, nullptr, SYSTEM_DRIVE_ENV) == 0) {
		if (!buffer || strlen(buffer) == 0) {
			throw PathHelperException("Failed to get SystemDrive environment variable");
		}
		if constexpr (IsUnicodeString<InputString>) {
			size_t len = strlen(buffer);
			systemDrive.resize(len);
			mbstowcs_s(nullptr, systemDrive.data(), len + 1, buffer, len);
		}
		else {
			systemDrive = InputString(buffer);
		}
		systemDrive += typename InputString::value_type('\\');
		SafeFree(buffer);
	}

	size_t systemDirPos = path.find(systemDir);

	if (systemDirPos != InputString::npos) {
		result.replace(systemDirPos, systemDir.length(), nativeWindowsPath);
		return result;
	}
	size_t drivePos = path.find(systemDrive);

	if (drivePos != InputString::npos) {
		OutputString ntDrive;

		if constexpr (IsUnicodeString<OutputString>) {
			ntDrive = OutputString(std::begin(NT_DRIVE_PREFIX), std::end(NT_DRIVE_PREFIX) - 1);
		}
		else {
			ntDrive = OutputString(NT_DRIVE_PREFIX);
		}

		ntDrive += OutputString(systemDrive.begin(), systemDrive.end());
		result.replace(drivePos, systemDrive.length(), ntDrive);
	}
	return result;
}
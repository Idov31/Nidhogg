#include "pch.h"
#include "Helper.h"

bool EnableColors() {
	DWORD oldMode = 0;
	DWORD newMode = 0;
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

	if (!hConsole || hConsole == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to get console handle" << std::endl;
		return false;
	}
	if (!GetConsoleMode(hConsole, &oldMode)) {
		std::cerr << "Failed to get console mode" << std::endl;
		return false;
	}
	newMode = oldMode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	
	if (!SetConsoleMode(hConsole, newMode)) {
		std::cerr << "Failed to set console mode" << std::endl;
		return false;
	}
	return true;
}

/*
* Description:
* ToLower is responsible for converting a string to lowercase.
* 
* Parameters:
* @str [_Inout_ std::string&] -- The string to be converted to lowercase.
* 
* Returns:
* There is no return value, the string is modified in place.
*/
void ToLower(_Inout_ std::string& str) {
	for (char& c : str) {
		c = static_cast<char>(std::tolower(c));
	}
}

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
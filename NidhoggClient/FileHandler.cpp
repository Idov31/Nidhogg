#include "FileHandler.h"

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
void FileHandler::HandleCommand(_In_ std::string command) {
	std::vector<std::string> params = SplitStringBySpace(command);
	std::string commandName = params.at(0);
	params.erase(params.begin());

	if (commandName.compare("add") == 0 || commandName.compare("protect") == 0) {
		if (params.size() != 2) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}
		std::wstring filePath = std::wstring(params.at(1).begin(), params.at(1).end());
		Protect(filePath, true) ? std::wcout << filePath.c_str() << L" is protected" << std::endl :
			std::wcerr << L"Failed to protect " << filePath.c_str() << std::endl;
	}
	else if (commandName.compare("remove") == 0 || commandName.compare("unprotect") == 0) {
		if (params.size() != 2) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}
		std::wstring filePath = std::wstring(params.at(1).begin(), params.at(1).end());
		Protect(filePath, false) ? std::wcout << L"Removed protection from " << filePath.c_str() << std::endl :
			std::wcerr << L"Failed to remove protection from " << filePath.c_str() << std::endl;
	}
	else if (commandName.compare("list") == 0) {
		std::vector<std::wstring> protectedFiles = {};

		if (params.size() != 1) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}
		std::string processType = params.at(0);

		try {
			protectedFiles = ListProtectedFiles();
		}
		catch (const FileHandlerException& e) {
			std::cerr << "Error: " << e.what() << std::endl;
			return;
		}
		std::cout << "[+] Protected files:" << std::endl;

		for (std::wstring& file : protectedFiles) {
			std::wcout << L"\t" << file.c_str() << std::endl;
		}
	}
	else if (commandName.compare("clear") == 0) {
		if (params.size() != 1) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}
		ClearProtectedFiles();
	}
	else {
		std::cerr << "Invalid option!" << std::endl;
		PrintHelp();
	}
}

/*
* Description:
* Protect is responsible for protecting or unprotecting a file path from being deleted.
*
* Parameters:
* @filePath [_In_ std::wstring] -- The file path to be protected or unprotected.
* @protect  [_In_ bool]			-- Whether to protect or unprotect the file.
*
* Returns:
* @bool						    -- Whether the operation was successful or not.
*/
bool FileHandler::Protect(_In_ std::wstring filePath, _In_ bool protect) {
	DWORD returned = 0;
	ProtectedFile protectedFile = { &filePath[0], protect};

	if (filePath.length() > MAX_PATH)
		return false;

	if (!DeviceIoControl(this->hNidhogg.get(), IOCTL_PROTECT_UNPROTECT_FILE,
		&protectedFile, sizeof(protectedFile),
		nullptr, 0, &returned, nullptr))
		return false;

	return true;
}

/*
* Description:
* ListProtectedFiles is responsible for listing all currently protected files.
*
* Parameters:
* There are no parameters
*
* Returns:
* @files [std::vector<std::wstring>] -- A vector containing the paths of all protected files.
*/
std::vector<std::wstring> FileHandler::ListProtectedFiles() {
	DWORD returned = 0;
	FileItem result{};
	std::vector<std::wstring> files = {};
	int amountOfFiles = 0;
	result.FileIndex = 0;

	if (!DeviceIoControl(hNidhogg.get(), IOCTL_QUERY_FILES,
		nullptr, 0,
		&result, sizeof(result), &returned, nullptr))
		throw FileHandlerException("Failed to get the protected files count.");
	amountOfFiles = result.FileIndex;

	if (amountOfFiles == 0)
		return files;

	files.push_back(std::wstring(result.FilePath));
	result.FilePath[0] = L'\0';

	for (int i = 1; i < amountOfFiles; i++) {
		result.FileIndex = i;

		if (!DeviceIoControl(hNidhogg.get(), IOCTL_QUERY_FILES,
			nullptr, 0,
			&result, sizeof(result), &returned, nullptr)) {

			files.clear();
			throw FileHandlerException("Failed to get the protected files.");
		}

		files.push_back(std::wstring(result.FilePath));
		result.FilePath[0] = L'\0';
	}

	return files;
}

/*
* Description:
* ClearProtectedFiles is responsible for clearing all protected files.
*
* Parameters:
* There are no parameters
*
* Returns:
* @bool						    -- Whether the operation was successful or not.
*/
bool FileHandler::ClearProtectedFiles() {
	DWORD returned = 0;

	return DeviceIoControl(this->hNidhogg.get(), IOCTL_CLEAR_FILE_PROTECTION,
		nullptr, 0, nullptr, 0, &returned, nullptr);
}

#include "pch.h"
#include "FileHandler.h"

/*
* Description:
* HandleCommand is responsible for handling a file related command.
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
		if (params.size() != 1) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}
		std::wstring filePath = std::wstring(params.at(0).begin(), params.at(0).end());
		Protect(filePath, true) ? std::wcout << filePath.c_str() << L" is protected" << std::endl :
			std::wcerr << L"Failed to protect " << filePath.c_str() << L": " << GetLastError() << std::endl;
	}
	else if (commandName.compare("remove") == 0 || commandName.compare("unprotect") == 0) {
		if (params.size() != 1) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}
		std::wstring filePath = std::wstring(params.at(0).begin(), params.at(0).end());
		Protect(filePath, false) ? std::wcout << L"Removed protection from " << filePath.c_str() << std::endl :
			std::wcerr << L"Failed to remove protection from " << filePath.c_str() << L": " << GetLastError() << std::endl;
	}
	else if (commandName.compare("list") == 0) {
		std::vector<std::wstring> protectedFiles = {};

		if (params.size() != 1) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}
		std::string fileType = params.at(0);

		if (fileType.compare("protected") == 0) {
			try {
				protectedFiles = ListFiles(FileType::Protected);
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
		else {
			std::cerr << "Invalid option!" << std::endl;
			PrintHelp();
		}
	}
	else if (commandName.compare("clear") == 0) {
		if (params.size() != 1) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}
		std::string fileType = params.at(0);

		if (fileType.compare("all") == 0)
			ClearFiles(FileType::All) ? std::cout << "All protected files cleared" << std::endl :
			std::cerr << "Failed to clear all protected files" << std::endl;
		else if (fileType.compare("protected") == 0)
			ClearFiles(FileType::Protected) ? std::cout << "Protected files cleared" << std::endl :
			std::cerr << "Failed to clear protected files" << std::endl;
		else {
			std::cerr << "Invalid option!" << std::endl;
			PrintHelp();
		}
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
	std::wstring parsedPath = L"";

	if (!IsValidPath(filePath))
		return false;

	try {
		parsedPath = ParsePath<std::wstring, std::wstring>(filePath);
	}
	catch (PathHelperException& e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return false;
	}
	IoctlFileItem protectedFile = { parsedPath.data(), protect};

	if (!DeviceIoControl(*hNidhogg.get(), IOCTL_PROTECT_UNPROTECT_FILE,
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
* @type  [_In_ FileType]			 -- The type of files to be listed (protected).
*
* Returns:
* @files [std::vector<std::wstring>] -- A vector containing the paths of all protected files.
*/
std::vector<std::wstring> FileHandler::ListFiles(_In_ FileType type) {
	DWORD returned = 0;
	std::vector<std::wstring> files = {};
	IoctlFileList result{};
	result.Type = type;

	auto CleanList = [&]() {
		if (result.Files) {
			for (SIZE_T i = 0; i < result.Count; i++) {
				SafeFree(result.Files[i]);
			}
			SafeFree(result.Files);
		}
	};

	if (!DeviceIoControl(*hNidhogg.get(), IOCTL_LIST_FILES, nullptr, 0, &result, sizeof(result), &returned, nullptr))
		throw FileHandlerException("Failed to get the protected files count.");

	if (result.Count > 0) {
		try {
			result.Files = SafeAlloc<wchar_t**>(result.Count * sizeof(wchar_t*));

			for (SIZE_T i = 0; i < result.Count; i++)
				result.Files[i] = SafeAlloc<wchar_t*>(MAX_PATH * sizeof(wchar_t));
		}
		catch (SafeMemoryException&) {
			CleanList();
			throw FileHandlerException("Failed to allocate memory for file list.");

		}

		if (!DeviceIoControl(*hNidhogg.get(), IOCTL_LIST_FILES, &result, sizeof(result), &result, sizeof(result), &returned,
			nullptr)) {
			CleanList();
			throw FileHandlerException("Failed to get the protected files.");
		}

		for (SIZE_T i = 0; i < result.Count; i++)
			files.push_back(std::wstring(result.Files[i]));
		CleanList();
	}
	return files;
}

/*
* Description:
* ClearFiles is responsible for clearing all protected files.
*
* Parameters:
* @type [_In_ FileType] -- The type of files to be cleared (protected).
*
* Returns:
* @bool				    -- Whether the operation was successful or not.
*/
bool FileHandler::ClearFiles(_In_ FileType type) {
	DWORD returned = 0;

	return DeviceIoControl(*hNidhogg.get(), IOCTL_CLEAR_PROTECTED_FILES,
		&type, sizeof(type), nullptr, 0, &returned, nullptr);
}

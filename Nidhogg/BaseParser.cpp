#include "pch.h"
#include "BaseParser.h"

BaseParser::~BaseParser() {
	if (this->options) {
		ExFreePoolWithTag(this->options, DRIVER_TAG);
		this->options = nullptr;
	}
}

NTSTATUS BaseParser::Execute(Options commandId, PVOID args[MAX_ARGS]) {
	UNREFERENCED_PARAMETER(commandId);
	UNREFERENCED_PARAMETER(args);
	return STATUS_SUCCESS;
}

/*
* Description:
* ExecuteCommand is responsible for parsing the arguments and executing the command.
*
* Parameters:
* @argsNumber [USHORT]	 -- Number of arguments to run.
* @data		  [PUCHAR]	 -- The raw script data.
* @dataSize	  [size_t]	 -- Size if the raw script data.
* @index	  [size_t]	 -- Index to start parsing the args and command from.
* @outOffset  [ULONG*]	 -- Output offset to shift the index by for the next command.
*
* Returns:
* @status	  [NTSTATUS] -- Result of the command execution or error if failed.
*/
NTSTATUS BaseParser::ExecuteCommand(USHORT argsNumber, PUCHAR data, size_t dataSize, size_t index, ULONG* outOffset) {
	PVOID args[MAX_ARGS] = { 0 };
	Options commandId;
	NTSTATUS status = STATUS_SUCCESS;

	status = ParseArgs(data, dataSize, index, argsNumber, &commandId, outOffset, args);

	if (!NT_SUCCESS(status))
		return status;

	__try {
		status = Execute(commandId, args);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}

	for (USHORT i = 0; i < argsNumber; i++) {
		if (args[i]) {
			ExFreePoolWithTag(args[i], DRIVER_TAG);
			args[i] = nullptr;
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
* @commandId  [Options*] -- The command id.
* @outOffset  [ULONG*]	 -- Output offset to shift the index by for the next command.
* @OutArgs    [PVOID*]	 -- Output arguments.
*
* Returns:
* @status	  [NTSTATUS] -- Whether the args are parsed or error.
*/
NTSTATUS BaseParser::ParseArgs(PUCHAR data, size_t dataSize, size_t index, USHORT argsNumber, Options* commandId,
	ULONG* outOffset, PVOID OutArgs[MAX_ARGS]) {
	USHORT optionIndex = 0;
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

		OutArgs[argIndex] = (PVOID)AllocateMemory(argSize);

		if (!OutArgs[argIndex]) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		RtlZeroMemory(OutArgs[argIndex], argSize);

		__try {
			RtlCopyMemory(OutArgs[argIndex], &data[currentIndex + 1], argSize);
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
				if (isdigit(((char*)OutArgs[argIndex])[j]) == 0) {
					status = STATUS_INVALID_PARAMETER;
					break;
				}
				intArg += convertDigit(((char*)OutArgs[argIndex])[j]) * factor;
			}
			*(ULONG*)OutArgs[argIndex] = intArg;
			intArg = 0;
			break;
		}
		case ArgType::CharPtr:
		case ArgType::WCharPtr:
		{
			for (DWORD j = 0; j < argSize; j++) {
				if (!isChar(((char*)OutArgs[argIndex])[j])) {
					status = STATUS_INVALID_PARAMETER;
					break;
				}
			}
			break;
		}
		}

		if (!NT_SUCCESS(status))
			break;

		addedOffset += argSize;
	}

	if (!NT_SUCCESS(status)) {
		for (USHORT i = 0; i < argIndex; i++) {
			if (OutArgs[i])
				ExFreePoolWithTag(OutArgs[i], DRIVER_TAG);
		}
	}

	*outOffset += addedOffset;
	return status;
}
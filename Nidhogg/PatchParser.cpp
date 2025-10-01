#include "pch.h"
#include "PatchParser.h"
#include "MemoryHandler.h"
#include "ProcessHandler.h"

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
NTSTATUS PatchParser::Execute(Options commandId, PVOID args[MAX_ARGS]) {
	UNREFERENCED_PARAMETER(commandId);

	IoctlPatchedModule patchedModule{};
	ANSI_STRING aModuleName = { 0 };
	UNICODE_STRING wModuleName = { 0 };
	NTSTATUS status = STATUS_SUCCESS;

	if (!Features.FunctionPatching)
		return STATUS_UNSUCCESSFUL;

	patchedModule.Pid = *(ULONG*)args[0];

	if (!IsValidPid(patchedModule.Pid))
		return STATUS_INVALID_PARAMETER;

	// Converting string to unicode.
	RtlInitAnsiString(&aModuleName, (PCHAR)args[1]);
	status = RtlAnsiStringToUnicodeString(&wModuleName, &aModuleName, TRUE);

	if (!NT_SUCCESS(status))
		return status;

	patchedModule.ModuleName = wModuleName.Buffer;
	patchedModule.FunctionName = (PCHAR)args[2];
	patchedModule.Patch = (PVOID)args[3];
	patchedModule.PatchLength = *(ULONG*)args[4];

	status = NidhoggMemoryHandler->PatchModule(&patchedModule);

	RtlFreeUnicodeString(&wModuleName);
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
NTSTATUS PatchParser::ParseArgs(PUCHAR data, size_t dataSize, size_t index, USHORT argsNumber, Options* commandId,
	ULONG* outOffset, PVOID OutArgs[MAX_ARGS]) {
	*commandId = Options::Invalid;
	ULONG addedOffset = 0;
	ULONG patchSize = 0;
	NTSTATUS status = STATUS_SUCCESS;

	if (!OutArgs)
		return STATUS_INVALID_PARAMETER;

	// Validating the opcode size.
	if (dataSize < index + 1)
		return STATUS_INVALID_BUFFER_SIZE;

	if (argsNumber != 4)
		return STATUS_INVALID_PARAMETER;

	// Check the option exists for the command type.
	auto CheckArg = [&](PUCHAR data, size_t dataSize, ULONG currentIndex, ArgType expectedType,
		USHORT argIndex, PVOID OutArgs[MAX_ARGS], ULONG* addedOffset, ULONG* size = NULL) {

		ULONG intArg = 0;

		if (dataSize < currentIndex)
			return STATUS_INVALID_BUFFER_SIZE;

		ULONG argSize = data[currentIndex];

		// Validating the size.
		if (argSize > dataSize - currentIndex)
			return STATUS_INVALID_BUFFER_SIZE;

		if (size)
			*size = argSize;

		PVOID currentArg = AllocateMemory<PVOID>(argSize);

		if (!currentArg)
			return STATUS_INSUFFICIENT_RESOURCES;

		RtlZeroMemory(currentArg, argSize);

		__try {
			RtlCopyMemory(currentArg, &data[currentIndex + 1], argSize);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			ExFreePoolWithTag(currentArg, DRIVER_TAG);
			return STATUS_ABANDONED;
		}

		// Validating the type.
		switch (expectedType) {
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
					ExFreePoolWithTag(currentArg, DRIVER_TAG);
					return STATUS_INVALID_PARAMETER;
				}
			}
			break;
		}
		}

		OutArgs[argIndex] = currentArg;
		*addedOffset += argSize;
		return STATUS_SUCCESS;
	};
	
	// Validating each argument.
	do {
		status = CheckArg(data, dataSize, (ULONG)index + addedOffset, ArgType::ULong, 0, OutArgs, &addedOffset);

		if (!NT_SUCCESS(status))
			break;
		status = CheckArg(data, dataSize, (ULONG)index + addedOffset + 1, ArgType::WCharPtr, 1, OutArgs, &addedOffset);

		if (!NT_SUCCESS(status))
			break;
		status = CheckArg(data, dataSize, (ULONG)index + addedOffset + 2, ArgType::CharPtr, 2, OutArgs, &addedOffset);

		if (!NT_SUCCESS(status))
			break;
		status = CheckArg(data, dataSize, (ULONG)index + addedOffset + 3, ArgType::ULong, 3, OutArgs, &addedOffset,
			&patchSize);
	} while (false);

	// Adding the patch size to the args.
	OutArgs[MAX_ARGS - 1] = (PVOID)patchSize;

	if (!NT_SUCCESS(status)) {
		if (OutArgs) {
			for (USHORT i = 0; i < MAX_ARGS - 1; i++) {
				if (OutArgs[i])
					ExFreePoolWithTag(OutArgs[i], DRIVER_TAG);
			}
		}
	}

	*outOffset += addedOffset;
	return status;
}
#include "pch.h"
#include "ScriptManager.h"

ScriptManager::ScriptManager() {
	for (USHORT i = 0; i < AMOUNT_OF_PARSERS; i++) {
		parsers[i].Handler = nullptr;
	}

	__try {
		parsers[(USHORT)ParserOpcode::Process] = { (USHORT)ParserOpcode::Process, new ProcessParser() };
		parsers[(USHORT)ParserOpcode::Thread] = { (USHORT)ParserOpcode::Thread, new ThreadParser() };
		parsers[(USHORT)ParserOpcode::Module] = { (USHORT)ParserOpcode::Module, new ModuleParser() };
		parsers[(USHORT)ParserOpcode::Driver] = { (USHORT)ParserOpcode::Driver, new DriverParser() };
		parsers[(USHORT)ParserOpcode::File] = { (USHORT)ParserOpcode::File, new FileParser() };
		parsers[(USHORT)ParserOpcode::Reg] = { (USHORT)ParserOpcode::Reg, new RegistryParser() };
		parsers[(USHORT)ParserOpcode::Patch] = { (USHORT)ParserOpcode::Patch, new PatchParser() };
		parsers[(USHORT)ParserOpcode::Shinject] = { (USHORT)ParserOpcode::Shinject, new ShellcodeInjectionParser() };
		parsers[(USHORT)ParserOpcode::Dllinject] = { (USHORT)ParserOpcode::Dllinject, new DllInjectionParser() };
		parsers[(USHORT)ParserOpcode::Callbacks] = { (USHORT)ParserOpcode::Callbacks, new CallbacksParser() };
		parsers[(USHORT)ParserOpcode::Etwti] = { (USHORT)ParserOpcode::Etwti, new EtwTiParser() };
		parsers[(USHORT)ParserOpcode::Port] = { (USHORT)ParserOpcode::Port, new NetworkParser() };
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
	}
}

ScriptManager::~ScriptManager() {
	for (USHORT i = 0; i < AMOUNT_OF_PARSERS; i++) {
		if (parsers[i].Handler) {
			delete parsers[i].Handler;
			parsers[i].Handler = nullptr;
		}
	}
}

/*
* Description:
* ExecuteScript is responsible for executing a Nidhogg script and returning the result of the execution.
*
* Parameters:
* @Script     [PUCHAR]	 -- Script to execute.
* @ScriptSize [ULONG]	 -- Size of the script.
*
* Returns:
* @status	  [NTSTATUS] -- Result of the script execution or error if failed.
*/
NTSTATUS ScriptManager::ExecuteScript(PUCHAR Script, ULONG ScriptSize) {
	ULONG offset = 0;
	NTSTATUS status = STATUS_SUCCESS;

	// Checking minimum size.
	if (ScriptSize < MINIMUM_SCRIPT_SIZE)
		return STATUS_INVALID_BUFFER_SIZE;

	// Checking signature.
	if (RtlCompareMemory(Script, SIGNATURE, sizeof(SIGNATURE)) != sizeof(SIGNATURE))
		return STATUS_INVALID_PARAMETER;

	// Checking commands size.
	ULONG commandsSize = Script[4];

	if (commandsSize == 0)
		return STATUS_INVALID_BUFFER_SIZE;

	for (ULONG i = 0; i < commandsSize; i++) {
		status = ExecuteCommand(Script, ScriptSize, FIRST_COMMAND_OFFSET + offset + i, &offset);

		if (!NT_SUCCESS(status))
			break;
	}
	return status;
}

/*
* Description:
* ExecuteCommand is responsible for executing a single command from script.
*
* Parameters:
* @data       [PUCHAR]	 -- Script to execute.
* @dataSize   [ULONG]	 -- Size of the script.
* @index	  [ULONG]	 -- Current index in the script.
* @outOffset  [ULONG*]	 -- The new offset to change the index by.
*
* Returns:
* @status	  [NTSTATUS] -- Result of the script execution or error if failed.
*/
NTSTATUS ScriptManager::ExecuteCommand(PUCHAR data, ULONG dataSize, ULONG index, ULONG* outOffset) {
	USHORT commandType = data[index];

	if (commandType > AMOUNT_OF_PARSERS - 1)
		return STATUS_INVALID_PARAMETER;

	*outOffset += 1;
	USHORT argsNumber = data[index + 1];

	if (argsNumber > 0) {
		*outOffset += 1;
		argsNumber = (ParserOpcode)commandType == ParserOpcode::Patch ? argsNumber : argsNumber - 1;

		// offset + 2 because of the args number and the command type.
		return this->parsers[commandType].Handler->ExecuteCommand(argsNumber, data, dataSize, (size_t)index + 2, outOffset);
	}

	return STATUS_INVALID_PARAMETER;
}
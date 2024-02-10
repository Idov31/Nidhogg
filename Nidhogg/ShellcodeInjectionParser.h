#pragma once
#include "pch.h"
#include "BaseParser.h"

constexpr ULONG MAX_PARAMS = 4;

class ShellcodeInjectionParser : public BaseParser
{
private:
	SIZE_T* paramsSize;

protected:
	NTSTATUS Execute(Options commandId, PVOID args[MAX_ARGS]) override;
	NTSTATUS ParseArgs(PUCHAR data, size_t dataSize, size_t index, USHORT argsNumber, Options* commandId,
		ULONG* outOffset, PVOID OutArgs[MAX_ARGS]) override;

public:
	ShellcodeInjectionParser();
	~ShellcodeInjectionParser();
};


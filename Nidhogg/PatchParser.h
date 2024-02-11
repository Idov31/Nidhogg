#pragma once
#include "pch.h"
#include "BaseParser.h"

class PatchParser : public BaseParser
{
protected:
	NTSTATUS Execute(Options commandId, PVOID args[MAX_ARGS]) override;
	NTSTATUS ParseArgs(PUCHAR data, size_t dataSize, size_t index, USHORT argsNumber, Options* commandId,
		ULONG* outOffset, PVOID OutArgs[MAX_ARGS]) override;

public:
	PatchParser() { this->optionsSize = 0; }
};


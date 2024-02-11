#pragma once
#include "pch.h"
#include "BaseParser.h"

class NetworkParser : public BaseParser
{
protected:
	NTSTATUS Execute(Options commandId, PVOID args[MAX_ARGS]) override;

public:
	NetworkParser();
};


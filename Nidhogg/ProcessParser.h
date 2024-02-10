#pragma once
#include "pch.h"
#include "BaseParser.h"

class ProcessParser : public BaseParser
{
protected:
	NTSTATUS Execute(Options commandId, PVOID args[MAX_ARGS]) override;

public:
	ProcessParser();
};


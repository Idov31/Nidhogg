#pragma once
#include "pch.h"
#include "BaseParser.h"

class EtwTiParser : public BaseParser
{
protected:
	NTSTATUS Execute(Options commandId, PVOID args[MAX_ARGS]) override;

public:
	EtwTiParser();
};


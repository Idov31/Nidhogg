#pragma once
#include "pch.h"
#include "Parsers.h"

// NDHG signature.
constexpr UCHAR SIGNATURE[] = { 0x4e, 0x44, 0x48, 0x47 };
constexpr size_t MINIMUM_SCRIPT_SIZE = sizeof(SIGNATURE) + 3;
constexpr size_t FIRST_COMMAND_OFFSET = sizeof(SIGNATURE) + 1;
constexpr USHORT AMOUNT_OF_PARSERS = 12;

struct ScriptInformation {
	PVOID Script;
	ULONG ScriptSize;
};

struct ParserItem {
	USHORT Opcode;
	BaseParser* Handler;
};

class ScriptManager
{
private:
	ParserItem parsers[AMOUNT_OF_PARSERS];
	NTSTATUS ExecuteCommand(PUCHAR data, ULONG dataSize, ULONG index, ULONG* outOffset);

public:
	void* operator new(size_t size) {
		return AllocateMemory(size, false);
	}

	void operator delete(void* p) {
		if (p)
			ExFreePoolWithTag(p, DRIVER_TAG);
	}

	ScriptManager();
	~ScriptManager();

	NTSTATUS ExecuteScript(PUCHAR Script, ULONG ScriptSize);
};


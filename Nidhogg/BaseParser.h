#pragma once
#include "pch.h"
#include "MemoryAllocator.hpp"

constexpr SIZE_T MAX_ARGS = 5;
constexpr SIZE_T MAX_TYPES = 6;

enum class ArgType {
	ULong,
	CharPtr,
	WCharPtr,
	VoidPtr,
};

enum class ParserOpcode {
	Process,
	Thread,
	Module,
	Driver,
	File,
	Reg,
	Patch,
	Shinject,
	Dllinject,
	Callbacks,
	Etwti,
	Port,
	Unknown = 0xFF
};

enum class Options {
	Add, Remove,
	Clear, Hide,
	Unhide, Elevate,
	Signature, APC,
	Thread,
	Enable = 0, Disable = 1,
	Restore = 0,
	Invalid = 0xFF
};

typedef struct _ArgMetadata {
	USHORT ArgsNumber;
	ArgType Types[MAX_TYPES];
} ArgMetadata;

struct OptionMetadata {
	Options OptionOpcode;
	ArgMetadata ArgMetadata;
};

class BaseParser
{
protected:
	OptionMetadata* options;
	ULONG optionsSize;

	constexpr bool isChar(char c) {
		return c >= ' ' && c <= '~';
	}

	constexpr USHORT convertDigit(char c) {
		return c - '0';
	}

	constexpr ULONG pow(ULONG base, ULONG exp) {
		ULONG result = 1;

		for (ULONG i = 0; i < exp; i++)
			result *= base;

		return result;
	}

	virtual NTSTATUS Execute(Options commandId, PVOID args[MAX_ARGS]);

	virtual NTSTATUS ParseArgs(PUCHAR data, size_t dataSize, size_t index, USHORT argsNumber, Options* commandId,
		ULONG* outOffset, PVOID OutArgs[MAX_ARGS]);
public:
	void* operator new(size_t size) {
		return AllocateMemory(size, false);
	}

	void operator delete(void* p) {
		if (p)
			ExFreePoolWithTag(p, DRIVER_TAG);
	}

	BaseParser() {
		options = nullptr;
		optionsSize = 0;
	}
	virtual ~BaseParser();

	virtual NTSTATUS ExecuteCommand(USHORT argsNumber, PUCHAR data, size_t dataSize, size_t index, ULONG* outOffset);
};


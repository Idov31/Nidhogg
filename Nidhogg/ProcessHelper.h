#pragma once
#include "pch.h"
#include "WindowsTypes.h"
#include "MemoryHelper.hpp"

constexpr SIZE_T SYSTEM_PROCESS_PID = 0x4;
constexpr SIZE_T PROCESS_TERMINATE = 0x1;
constexpr SIZE_T PROCESS_CREATE_THREAD = 0x2;
constexpr SIZE_T PROCESS_VM_READ = 0x10;
constexpr SIZE_T PROCESS_VM_OPERATION = 0x8;

_IRQL_requires_max_(APC_LEVEL)
ULONG FindPidByName(_In_ const wchar_t* processName);

constexpr auto IsValidPid = [](ULONG pid) -> bool {
	return pid > SYSTEM_PROCESS_PID;
};
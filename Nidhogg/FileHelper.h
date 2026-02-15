#pragma once
#include "pch.h"
#include "MemoryAllocator.hpp"

constexpr WCHAR NTFS_DRIVER_PATH[] = L"\\FileSystem\\NTFS";
constexpr WCHAR CURRENT_VERSION_REGISTRY_KEY[] = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion";
constexpr WCHAR PROGRAM_FILES_VALUE[] = L"ProgramFilesDir";
constexpr SIZE_T MAX_REG_VALUE_SIZE = 256;
constexpr SIZE_T DRIVE_LETTER_SIZE = 2;
constexpr SIZE_T NT_PREFIX_SIZE = 4;
constexpr SIZE_T MAX_PATH = 260;

_IRQL_requires_max_(PASSIVE_LEVEL)
WCHAR* GetMainDriveLetter();

_IRQL_requires_max_(DISPATCH_LEVEL)
bool IsValidPath(_In_ WCHAR* path);

_IRQL_requires_max_(DISPATCH_LEVEL)
bool IsValidPath(_In_ char* path);

_IRQL_requires_max_(PASSIVE_LEVEL)
bool IsFileExists(_In_ WCHAR* filePath);

_IRQL_requires_max_(PASSIVE_LEVEL)
bool IsFileExists(_In_ char* filePath);
#pragma once
#include "pch.h"
#include "IoctlShared.h"
#include "WindowsTypes.h"
#include "MemoryAllocator.hpp"
#include "FileHelper.h"
#include "MemoryHelper.h"

// Definitions.
constexpr ULONG IMAGE_SCN_MEM_EXECUTE = 0x20000000;
constexpr UINT32 MAX_OFFSET = 0xffffffff;
constexpr SIZE_T COFF_FUNMAP_SIZE = 2048;
constexpr CHAR SYMBOL_DELIMITER[] = "$";
constexpr CHAR IMPORT_FUNCTION_PREFIX[] = "__imp_";
constexpr CHAR NTOSKRNL_SYMBOL[] = "ntoskrnl";
constexpr CHAR NIDHOGG_SYMBOL[] = "nidhogg";
constexpr CHAR NTDLL_SYMBOL[] = "ntdll";

// Structures.
#pragma pack(push,1)
typedef struct _COFF_FILE_HEADER
{
    UINT16  Machine;
    UINT16  NumberOfSections;
    UINT32  TimeDateStamp;
    UINT32  PointerToSymbolTable;
    UINT32  NumberOfSymbols;
    UINT16  SizeOfOptionalHeader;
    UINT16  Characteristics;
} COFF_FILE_HEADER, * PCOFF_FILE_HEADER;

typedef struct _COFF_SECTION
{
    CHAR    Name[8];
    UINT32  VirtualSize;
    UINT32  VirtualAddress;
    UINT32  SizeOfRawData;
    UINT32  PointerToRawData;
    UINT32  PointerToRelocations;
    UINT32  PointerToLineNumbers;
    UINT16  NumberOfRelocations;
    UINT16  NumberOfLinenumbers;
    UINT32  Characteristics;
} COFF_SECTION, * PCOFF_SECTION;

typedef struct _COFF_RELOC
{
    UINT32  VirtualAddress;
    UINT32  SymbolTableIndex;
    UINT16  Type;
} COFF_RELOC, * PCOFF_RELOC;

typedef struct _COFF_SYMBOL
{
    union
    {
        CHAR    Name[8];
        UINT32  Value[2];
    } First;

    UINT32 Value;
    UINT16 SectionNumber;
    UINT16 Type;
    UINT8  StorageClass;
    UINT8  NumberOfAuxSymbols;
} COFF_SYMBOL, * PCOFF_SYMBOL;

typedef struct _SECTION_MAP
{
    PCHAR   Ptr;
    SIZE_T  Size;
} SECTION_MAP, * PSECTION_MAP;

typedef struct _COFF
{
    PVOID Data;
    SIZE_T DataSize;
    PCOFF_FILE_HEADER Header;
    PCOFF_SECTION Section;
    PCOFF_RELOC Reloc;
    PCOFF_SYMBOL Symbol;

    PSECTION_MAP SecMap;
    PCHAR FunMap;
} COFF, * PCOFF;
#pragma pack(pop)

typedef void(*tMainFunction)(PVOID data, SIZE_T dataSize);

class NofLoader {
private:
    COFF coff;
    PCHAR entryName;
	SIZE_T entryNameSize;
    PVOID parameter;
    SIZE_T parameterSize;
    PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt;

    _IRQL_requires_(PASSIVE_LEVEL)
    NTSTATUS ProcessSections();

    _IRQL_requires_(PASSIVE_LEVEL)
    PCHAR ProcessSymbol(_In_ LPSTR symbolName) const noexcept;

public:
    void* operator new(_In_ size_t size) {
		return AllocateMemory<PVOID>(size, false);
    }

    void operator delete(void* p) {
        if (p)
            ExFreePoolWithTag(p, DRIVER_TAG);
    }

    _IRQL_requires_max_(APC_LEVEL)
    NofLoader(_In_ IoctlCoff& coffData);

    _IRQL_requires_max_(APC_LEVEL)
    ~NofLoader();

    _IRQL_requires_(PASSIVE_LEVEL)
    NTSTATUS Load();

    _IRQL_requires_(PASSIVE_LEVEL)
    NTSTATUS Execute() const;
};


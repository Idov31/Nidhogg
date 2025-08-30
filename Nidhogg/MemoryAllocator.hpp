#pragma once
#include "pch.h"

template<typename DataType>
class MemoryAllocator {
private:
	DataType AllocatedData;
	SIZE_T AllocatedSize;

public:
	MemoryAllocator(DataType Data, SIZE_T Size) {
		this->AllocatedData = Data;
		this->AllocatedSize = Size;

		if (Size != 0) {
			Data = AllocateMemory<DataType>(Size);

			if (Data)
				memset(Data, 0, Size);
		}
	}
	MemoryAllocator(DataType* Data, SIZE_T Size) {
		this->AllocatedData = nullptr;
		this->AllocatedSize = Size;

		if (Size != 0) {
			*Data = AllocateMemory<DataType>(Size);

			if (*Data) {
				memset(*Data, 0, Size);
				this->AllocatedData = *Data;
			}
		}
	}
	~MemoryAllocator() {
		if (this->AllocatedData) {
			ExFreePoolWithTag(this->AllocatedData, DRIVER_TAG);
			this->AllocatedData = nullptr;
		}
	}

	NTSTATUS CopyData(DataType Data, SIZE_T Size) {
		SIZE_T bytesWritten = 0;
		NTSTATUS status = STATUS_INVALID_PARAMETER;

		if (!Data || !this->AllocatedData)
			return STATUS_INVALID_BUFFER_SIZE;

		if (Size > this->AllocatedSize)
			return status;

		status = MmCopyVirtualMemory(PsGetCurrentProcess(), Data, PsGetCurrentProcess(), this->AllocatedData, Size,
			KernelMode, &bytesWritten);

		if (NT_SUCCESS(status)) {
			status = bytesWritten == Size ? STATUS_SUCCESS : STATUS_INVALID_BUFFER_SIZE;
		}
		return status;
	}
};

template<typename DataType>
class WindowsMemoryAllocator {
private:
	HANDLE processHandle;
	PVOID baseAddress;
	SIZE_T allocatedSize;
	ULONG freeType;

public:
	_IRQL_requires_max_(APC_LEVEL)
	WindowsMemoryAllocator(_In_ HANDLE processHandle, _Inout_ PVOID baseAddress, _Inout_ SIZE_T* size, _In_ ULONG allocationType,
		_In_ ULONG freeType, _In_ ULONG protection, _Out_ NTSTATUS* status) noexcept {
		this->processHandle = processHandle;
		this->baseAddress = nullptr;
		this->allocatedSize = *size;
		this->freeType = freeType;

		if (size != 0 && processHandle != 0) {
			*status = ZwAllocateVirtualMemory(processHandle, &this->baseAddress, 0, size,
				allocationType, protection);

			if (NT_SUCCESS(status)) {
				this->baseAddress = baseAddress;
				memset(this->baseAddress, 0, allocatedSize);
			}
		}
	}

	_IRQL_requires_max_(APC_LEVEL)
	WindowsMemoryAllocator(_In_ PVOID baseAddress, _Inout_ SIZE_T* size, _In_ ULONG protection, _Out_ NTSTATUS* status) noexcept :
	WindowsMemoryAllocator(ZwCurrentProcess(), baseAddress, size, MEM_COMMIT | MEM_RESERVE, MEM_DECOMMIT, protection, status) {

	}

	_IRQL_requires_max_(APC_LEVEL)
	~WindowsMemoryAllocator() noexcept {
		if (this->baseAddress) {
			ZwFreeVirtualMemory(this->processHandle, &this->baseAddress, &this->allocatedSize, this->freeType);
		}
	}
};
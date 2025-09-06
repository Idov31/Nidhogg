#pragma once
#include "pch.h"
#include "NidhoggCommon.h"

template<typename DataType>
class MemoryAllocator {
private:
	DataType allocatedData;
	SIZE_T allocatedSize;

public:
	_IRQL_requires_max_(APC_LEVEL)
	MemoryAllocator(_Inout_ DataType data, _In_ SIZE_T size) noexcept {
		this->allocatedData = nullptr;
		this->allocatedSize = size;

		if (size != 0) {
			data = AllocateMemory<DataType>(size);

			if (data) {
				RtlSecureZeroMemory(data, size);
				this->allocatedData = data;
			}
		}
	}

	_IRQL_requires_max_(APC_LEVEL)
	MemoryAllocator(_Inout_ DataType* data, _In_ SIZE_T size) noexcept {
		this->allocatedData = nullptr;
		this->allocatedSize = size;

		if (size != 0) {
			*data = AllocateMemory<DataType>(size);

			if (*data) {
				RtlSecureZeroMemory(*data, size);
				this->allocatedData = *data;
			}
		}
	}

	_IRQL_requires_max_(APC_LEVEL)
	~MemoryAllocator() {
		FreeVirtualMemory<DataType>(this->allocatedData);
	}

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS CopyData(_In_ DataType data, _In_ SIZE_T size) {
		SIZE_T bytesWritten = 0;
		NTSTATUS status = STATUS_INVALID_PARAMETER;

		if (!allocatedData)
			return STATUS_INVALID_BUFFER_SIZE;

		if (!data || size > this->allocatedSize)
			return status;

		status = MmCopyVirtualMemory(PsGetCurrentProcess(), data, PsGetCurrentProcess(), this->allocatedData, size,
			KernelMode, &bytesWritten);

		if (NT_SUCCESS(status))
			status = bytesWritten == size ? STATUS_SUCCESS : STATUS_INVALID_BUFFER_SIZE;
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
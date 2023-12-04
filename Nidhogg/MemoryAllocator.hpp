#pragma once
#include "pch.h"

template<typename DataType>
class MemoryAllocator {
private:
	DataType AllocatedData;
	SIZE_T AllocatedSize;

public:
	MemoryAllocator(DataType Data, SIZE_T Size, POOL_TYPE PoolType) {
		this->AllocatedData = Data;
		this->AllocatedSize = Size;

		if (Size != 0) {
			Data = (DataType)ExAllocatePoolWithTag(PoolType, Size, DRIVER_TAG);

			if (Data)
				memset(Data, 0, Size);
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

		status = MmCopyVirtualMemory(PsGetCurrentProcess(), Data, PsGetCurrentProcess(), this->AllocatedData, Size, KernelMode, &bytesWritten);

		if (NT_SUCCESS(status)) {
			status = bytesWritten == Size ? STATUS_SUCCESS : STATUS_INVALID_BUFFER_SIZE;
		}
		return status;
	}
};

#pragma once
#include "pch.h"
#include "NidhoggCommon.h"
#include "WindowsTypes.h"
#include "IrqlGuard.h"

template <typename Ptr>
concept RegularPointerType = requires(Ptr ptr) {
	ptr != nullptr;
	sizeof(ptr) == sizeof(PVOID);
	*ptr;
};

template <typename Ptr>
concept VoidPointerType = requires(PVOID ptr) {
	ptr != nullptr;
	sizeof(ptr) == sizeof(PVOID);
};

template <typename Ptr>
concept PointerType = RegularPointerType<Ptr> || VoidPointerType<Ptr>;

/*
* Description:
* AllocateVirtualMemory is responsible for allocating virtual memory with the right function depends on the windows version.
*
* Parameters:
* @size				    [size_t]	  -- Size to allocate.
* @paged				[bool]		  -- Paged or non-paged.
* @forceDeprecatedAlloc [bool]		  -- Force allocation with ExAllocatePoolWithTag.
*
* Returns:
* @ptr					[Pointer] -- Allocated pointer on success else NULL.
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
template <PointerType Pointer>
inline Pointer AllocateMemory(size_t size, bool paged = true, bool forceDeprecatedAlloc = false) noexcept {
	PVOID allocatedMem = NULL;
	IrqlGuard guard = IrqlGuard();

	if (paged)
		guard.SetIrql(PASSIVE_LEVEL);

	if (AllocatePool2 && WindowsBuildNumber >= WIN_2004 && !forceDeprecatedAlloc) {
		allocatedMem = paged ? ((tExAllocatePool2)AllocatePool2)(POOL_FLAG_PAGED, size, DRIVER_TAG) :
			((tExAllocatePool2)AllocatePool2)(POOL_FLAG_NON_PAGED, size, DRIVER_TAG);
	}
	else {
#pragma warning(push)
#pragma warning(disable : 4996)
		allocatedMem = paged ? ExAllocatePoolWithTag(PagedPool, size, DRIVER_TAG) :
			ExAllocatePoolWithTag(NonPagedPool, size, DRIVER_TAG);
#pragma warning(pop)
	}

	if (allocatedMem)
		RtlSecureZeroMemory(allocatedMem, size);
	return reinterpret_cast<Pointer>(allocatedMem);
}

/*
* Description:
* FreeVirtualMemory is responsible for freeing virtual memory and null it.
*
* Parameters:
* @address [_Inout_ Pointer&] -- Address to free.
*
* Returns:
* There is no return value.
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
template <PointerType Pointer>
void FreeVirtualMemory(_Inout_ Pointer& address) {
	if (!address)
		return;
	ExFreePoolWithTag(address, DRIVER_TAG);
	address = NULL;
}

template<PointerType DataType>
class MemoryAllocator {
private:
	DataType allocatedData;
	SIZE_T allocatedSize;

public:
	_IRQL_requires_max_(DISPATCH_LEVEL)
	MemoryAllocator() noexcept {
		allocatedData = nullptr;
		allocatedSize = 0;
	}

	_IRQL_requires_max_(DISPATCH_LEVEL)
	MemoryAllocator(_In_ SIZE_T size) noexcept {
		allocatedData = nullptr;
		allocatedSize = 0;
		Alloc(size);
	}

	_IRQL_requires_max_(DISPATCH_LEVEL)
	bool IsValid() const {
		return allocatedSize > 0 && allocatedData;
	}

	_IRQL_requires_max_(DISPATCH_LEVEL)
	DataType Get() const {
		return allocatedData;
	}

	_IRQL_requires_max_(DISPATCH_LEVEL)
	bool Alloc(_In_ SIZE_T size) {
		if (size == 0 || allocatedData) {
			return false;
		}
		allocatedData = AllocateMemory<DataType>(size);

		if (allocatedData) {
			RtlSecureZeroMemory(allocatedData, size);
			this->allocatedSize = size;
			return true;
		}
		return false;
	}

	_IRQL_requires_max_(DISPATCH_LEVEL)
	bool Realloc(_Inout_ DataType data, _In_ SIZE_T size) {
		if (allocatedData)
			Free();
		return Alloc(size);
	}

	_IRQL_requires_max_(DISPATCH_LEVEL)
	void Free() {
		FreeVirtualMemory<DataType>(allocatedData);
		this->allocatedData = nullptr;
		this->allocatedSize = 0;
	}

	_IRQL_requires_max_(DISPATCH_LEVEL)
	~MemoryAllocator() {
		Free();
	}

	_IRQL_requires_max_(APC_LEVEL)
	NTSTATUS CopyData(_In_ DataType data, _In_ SIZE_T size, _In_ KPROCESSOR_MODE mode = KernelMode) {
		SIZE_T bytesWritten = 0;
		NTSTATUS status = STATUS_INVALID_PARAMETER;

		if (!allocatedData)
			return STATUS_INVALID_BUFFER_SIZE;

		if (!data || size > this->allocatedSize)
			return status;

		status = MmCopyVirtualMemory(PsGetCurrentProcess(), data, PsGetCurrentProcess(), this->allocatedData, size,
			mode, &bytesWritten);

		if (NT_SUCCESS(status))
			status = bytesWritten == size ? STATUS_SUCCESS : STATUS_INVALID_BUFFER_SIZE;
		return status;
	}
};

class MemoryGuard {
private:
	FastMutex lock;
	PMDL mdl;
	bool valid;

public:
	_IRQL_requires_max_(APC_LEVEL)
	MemoryGuard() {
		this->mdl = nullptr;
		this->valid = false;
		lock.Init();
	}

	_IRQL_requires_max_(APC_LEVEL)
	MemoryGuard(_In_ PVOID address, _In_ ULONG length, _In_ KPROCESSOR_MODE mode) noexcept {
		this->mdl = nullptr;
		this->valid = false;
		lock.Init();
		GuardMemory(address, length, mode);
	}

	_IRQL_requires_max_(APC_LEVEL)
	bool GuardMemory(_In_ PVOID address, _In_ ULONG length, _In_ KPROCESSOR_MODE mode) {
		UnguardMemory();

		AutoLock locker(lock);
		this->mdl = nullptr;
		this->valid = false;

		if (length != 0 && address) {
			this->mdl = IoAllocateMdl(address, length, FALSE, FALSE, NULL);

			if (this->mdl) {
				__try {
					MmProbeAndLockPages(this->mdl, mode, IoReadAccess);
					this->valid = true;
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					IoFreeMdl(this->mdl);
					this->mdl = nullptr;
				}
			}
		}

		return this->valid;
	}

	_IRQL_requires_max_(APC_LEVEL)
	void UnguardMemory() {
		AutoLock locker(this->lock);

		if (this->mdl) {
			if (this->valid) {
				MmUnlockPages(this->mdl);
				this->valid = false;
			}
			IoFreeMdl(this->mdl);
			this->mdl = nullptr;
		}
	}

	_IRQL_requires_max_(APC_LEVEL)
	bool IsValid() {
		AutoLock locker(this->lock);
		return this->valid;
	}

	_IRQL_requires_max_(APC_LEVEL)
	~MemoryGuard() noexcept {
		UnguardMemory();
	}
};
#pragma once
#include "pch.h"
#include "PushLock.h"
#include "AutoLock.h"
#include "NidhoggCommon.h"
#include "WindowsTypes.h"
#include "IrqlGuard.h"

constexpr auto IsValidUmMemory = [](_In_ ULONG64 address) { return address > 0 && address < 0x7FFFFFFFFFFFFFFF; };
constexpr auto IsValidKmMemory = [](_In_ ULONG64 address) { return address > 0x8000000000000000 && address < 0xFFFFFFFFFFFFFFFF; };

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
* @execute				[bool]		  -- Whether the allocated memory should be executable or not.
*
* Returns:
* @ptr					[Pointer] -- Allocated pointer on success else NULL.
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
template <PointerType Pointer>
inline Pointer AllocateMemory(size_t size, 
	bool paged = true, 
	bool forceDeprecatedAlloc = false, 
	bool execute = false) noexcept {
	PVOID allocatedMem = NULL;
	IrqlGuard guard = IrqlGuard();

	if (paged)
		guard.SetIrql(PASSIVE_LEVEL);

	if (AllocatePool2 && WindowsBuildNumber >= WIN_2004 && !forceDeprecatedAlloc) {
		POOL_FLAGS flags = paged ? POOL_FLAG_PAGED : POOL_FLAG_NON_PAGED;
		flags = execute ? POOL_FLAG_NON_PAGED_EXECUTE : flags;
		allocatedMem = ((tExAllocatePool2)AllocatePool2)(flags, size, DRIVER_TAG);
	}
	else {
		POOL_TYPE flags = paged ? PagedPool : NonPagedPool;
		flags = execute ? NonPagedPoolExecute : flags;
#pragma warning(push)
#pragma warning(disable : 4996)
		allocatedMem = ExAllocatePoolWithTag(flags, size, DRIVER_TAG);
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
	bool Realloc(_In_ SIZE_T size) {
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
	NTSTATUS CopyData(_In_ DataType data, _In_ SIZE_T size) {
		SIZE_T bytesWritten = 0;
		NTSTATUS status = STATUS_INVALID_PARAMETER;
		PEPROCESS currentProcess = PsGetCurrentProcess();

		if (!allocatedData)
			return STATUS_INVALID_BUFFER_SIZE;

		if (!data || size > this->allocatedSize)
			return status;

		status = MmCopyVirtualMemory(currentProcess, 
			data, 
			currentProcess, 
			this->allocatedData, 
			size,
			KernelMode, 
			&bytesWritten);

		if (NT_SUCCESS(status))
			status = bytesWritten == size ? STATUS_SUCCESS : STATUS_INVALID_BUFFER_SIZE;
		return status;
	}
};

class MemoryGuard {
private:
	PushLock lock;
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
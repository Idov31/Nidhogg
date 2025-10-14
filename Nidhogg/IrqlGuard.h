#pragma once
#include "pch.h"

class IrqlGuard {
private:
	KIRQL originalIrql;
	bool set;
public:
	_IRQL_requires_max_(HIGH_LEVEL)
	IrqlGuard() {
		set = false;
		originalIrql = KeGetCurrentIrql();
	}

	_IRQL_requires_max_(HIGH_LEVEL)
	IrqlGuard(_In_ KIRQL newIrql) {
		set = false;
		originalIrql = KeGetCurrentIrql();

		if (originalIrql != newIrql) {
			__writecr8(newIrql);
			set = true;
		}
	}

	_IRQL_requires_max_(HIGH_LEVEL)
	void SetIrql(_In_ KIRQL newIrql) {
		if (originalIrql != newIrql) {
			__writecr8(newIrql);
			set = true;
		}
	}

	_IRQL_requires_max_(HIGH_LEVEL)
	void SetExitIrql(_In_ KIRQL newIrql) {
		originalIrql = newIrql;
		set = true;
	}

	_IRQL_requires_max_(HIGH_LEVEL)
	void UnsetIrql() {
		if (set) {
			set = false;
			__writecr8(originalIrql);
		}
	}

	_IRQL_requires_max_(HIGH_LEVEL)
	~IrqlGuard() {
		UnsetIrql();
	}
};
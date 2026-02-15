#include "pch.h"
#include "PushLock.h"


void PushLock::Init() {
	ExInitializePushLock(&lock);
}

void PushLock::Lock() {
	ExAcquirePushLockExclusive(&lock);
}

void PushLock::Unlock() {
	ExReleasePushLockExclusiveEx(&lock, 0);
}
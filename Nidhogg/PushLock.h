#pragma once
#include "pch.h"

class PushLock {
private:
	EX_PUSH_LOCK lock;

public:
	void Init();

	void Lock();
	void Unlock();
};

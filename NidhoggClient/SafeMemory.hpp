#pragma once
#include "pch.h"

class SafeMemoryException : public std::runtime_error
{
	std::string msg;
public:
	SafeMemoryException(_In_ const std::string& message)
		: std::runtime_error(message), msg(message) {}
	const char* what() const override
	{
		return msg.c_str();
	}
};

/*
* Description:
* SafeFree is responsible for safely freeing a pointer and setting it to nullptr.
*
* Parameters:
* @ptr [_Inout_opt_ PVOID] -- The pointer to be freed.
*
* Returns:
* There is no return value.
*/
inline void SafeFree(_Inout_opt_ PVOID ptr) {
	if (ptr) {
		free(ptr);
		ptr = nullptr;
	}
}

/*
* Description:
* SafeAlloc is responsible for safely allocating memory of a given size.
*
* Parameters:
* @size [_In_ SIZE_T] -- The size of memory to be allocated.
*
* Returns:
* @ptr  [PVOID] -- The pointer to the allocated memory.
*/
template<typename Ptr>
inline Ptr SafeAlloc(_In_ SIZE_T size) {
	Ptr ptr = reinterpret_cast<Ptr>(malloc(size));

	if (!ptr)
		throw SafeMemoryException("Failed to allocate memory");
	memset(ptr, 0, size);
	return ptr;
}
#pragma once
#include "pch.h"

/*
* Description:
* wcisstr is responsible for comparing two wchar_t* and find if one contains the other (case insensitive).
*
* Parameters:
* @haystack [wchar_t*] -- Possible container.
* @needle	[wchar_t*] -- Possible contained.
*
* Returns:
* @status	[bool]	   -- Whether haystack is contains needle.
*/
bool wcisstr(wchar_t* haystack, wchar_t* needle) {
	int j = 0;
	size_t index = wcslen(haystack) - wcslen(needle);

	auto needleInHaystackLen = (wcslen(needle) + 1) * sizeof(WCHAR);
	auto needleInHaystack = (WCHAR*)ExAllocatePoolWithTag(PagedPool, needleInHaystackLen, DRIVER_TAG);

	if (!needleInHaystack)
		return false;

	for (size_t i = index; i < wcslen(haystack); i++) {
		if (j >= wcslen(needle))
			break;

		needleInHaystack[j] = haystack[i];
		j++;
	}

	needleInHaystack[wcslen(needle)] = L'\0';

	if (_wcsicmp(needleInHaystack, needle) == 0) {
		ExFreePoolWithTag(needleInHaystack, DRIVER_TAG);
		return true;
	}

	ExFreePoolWithTag(needleInHaystack, DRIVER_TAG);
	return false;
}

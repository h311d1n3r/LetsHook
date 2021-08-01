#pragma once
#include <windows.h>
#include <vector>
#define DllExport __declspec(dllexport)

DllExport struct REGION_SEARCH_DATA {
	DWORD AllocationProtect;
	DWORD Protect;
	SIZE_T* RegionSizes;
	int RegionSizesLen;
	DWORD State;
	DWORD Type;
};

DllExport std::vector<MEMORY_BASIC_INFORMATION> findRegions(REGION_SEARCH_DATA data);
#include "pch.h"
#include "ram_assembly_finder.h"
#include <iostream>

using namespace std;

DWORDLONG processTotalSize() {
	MEMORYSTATUSEX status = {};
	status.dwLength = sizeof(status);
	if (GlobalMemoryStatusEx(&status)) return status.ullTotalVirtual;
	return NULL;
}

BOOL grantRights(LPVOID regionBase, SIZE_T regionSize) {
	DWORD oldProtect;
	return VirtualProtect(regionBase, regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
}

vector<MEMORY_BASIC_INFORMATION> findRegions(REGION_SEARCH_DATA data) {
	vector<MEMORY_BASIC_INFORMATION> regions;
	if (DWORDLONG totalSize = processTotalSize()) {
		DWORDLONG index = 0;
		do {
			MEMORY_BASIC_INFORMATION regionInfo = {};
			if (VirtualQueryEx(GetCurrentProcess(), (LPCVOID)index, &regionInfo, sizeof(regionInfo))) {
				if (regionInfo.AllocationProtect == data.AllocationProtect &&
					(regionInfo.Protect == data.Protect || regionInfo.Protect == PAGE_EXECUTE_READWRITE) &&
					find(data.RegionSizes, data.RegionSizes + data.RegionSizesLen, regionInfo.RegionSize) != data.RegionSizes + data.RegionSizesLen &&
					regionInfo.State == data.State &&
					regionInfo.Type == data.Type) regions.push_back(regionInfo);
				index += regionInfo.RegionSize;
			}
			else break;
		} while (index < totalSize);
	}
	return regions;
}

DWORDLONG findAssemblyInRegion(ASSEMBLY_SEARCH_DATA data) {
	bool isRegionReady = true;
	if (data.region.Protect != PAGE_EXECUTE_READWRITE) {
		if (!grantRights(data.region.BaseAddress, data.region.RegionSize)) isRegionReady = false;
	}
	if (isRegionReady) {
		int sameCounter = 0;
		for (DWORDLONG index = (DWORDLONG)data.region.BaseAddress; index < (DWORDLONG)data.region.BaseAddress + data.region.RegionSize; index++) {
			char c = *((char*)index);
			if (c == data.assembly[sameCounter]) {
				sameCounter++;
				if (sameCounter == data.assemblyLen) return index - sameCounter + 1;
			}
			else if (sameCounter != 0) sameCounter = 0;
		}
	}
	return NULL;
}

DWORDLONG findAddress(REGION_SEARCH_DATA region_data, const char assembly[]) {
	vector<MEMORY_BASIC_INFORMATION> regions = findRegions(region_data);
	DWORDLONG addr = NULL;
	for (const MEMORY_BASIC_INFORMATION& region : regions) {
		if (addr = findAssemblyInRegion({ region,(char*)assembly,sizeof(assembly) })) break;
	}
	return addr;
}
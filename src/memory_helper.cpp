#include <memory_helper.h>
#include <psapi.h>
#include <map>

PatternMatcher::PatternMatcher() {
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	this->area = { (ADDR)info.lpMinimumApplicationAddress, (ADDR)info.lpMaximumApplicationAddress };
}

PatternMatcher::PatternMatcher(HMODULE mod) {
	MODULEINFO info;
	GetModuleInformation(GetCurrentProcess(), mod, &info, sizeof(MODULEINFO));
	this->area = { (ADDR)info.lpBaseOfDll, info.SizeOfImage };
}

SearchArea PatternMatcher::getSearchArea() {
	return this->area;
}

vector<ADDR> PatternMatcher::findMatches(PatternFilter filter) {
	vector<ADDR> matches;
	map<char, char> sameValsMap;
	vector<Region> regions = this->findCandidateRegions(filter);
	for (Region region : regions) {
		ADDR currentAddr = region.start;
		unsigned int currentIndex = 0;
		while (currentAddr < region.start + region.size) {
			char currentByte = *((char*) currentAddr);
			bool isValid = false;
			if (filter.sameVals && filter.sameVals[currentIndex] != 0) {
				char key = filter.sameVals[currentIndex];
				if (sameValsMap.count(key)) {
					if (sameValsMap[key] == currentByte) isValid = true;
				}
				else {
					sameValsMap[key] = currentByte;
					isValid = true;
				}
			}
			else if (currentByte == filter.assemblyCode[currentIndex]) isValid = true;
			if (isValid) {
				currentIndex++;
				if (currentIndex == filter.assemblyCodeSize) {
					matches.push_back(currentAddr - currentIndex + 1);
					if (filter.sameVals) sameValsMap.clear();
					currentIndex = 0;
				}
			}
			else {
				currentIndex = 0;
				if(filter.sameVals && sameValsMap.size()) sameValsMap.clear();
			}
			currentAddr++;
		}
	}
	return matches;
}

vector<Region> PatternMatcher::findCandidateRegions(PatternFilter filter) {
	vector<Region> matches;
	ADDR regionStart = area.start;
	ADDR prevRegionStart = regionStart - 1;
	while (regionStart < (ADDR)area.start + area.size && regionStart != prevRegionStart) {
		MEMORY_BASIC_INFORMATION regionInfo;
		VirtualQuery((LPCVOID)regionStart, &regionInfo, sizeof(regionInfo));
		if (!filter.allocProtect || regionInfo.AllocationProtect == filter.allocProtect) {
			if (!filter.protect || regionInfo.Protect == filter.protect) {
				if (!filter.type || regionInfo.Type == filter.type) {
					if (!filter.state || regionInfo.State == filter.state) {
						if (!filter.size || regionInfo.RegionSize == filter.size) {
							Region region = { (ADDR)regionInfo.BaseAddress, regionInfo.RegionSize };
							matches.push_back(region);
						}
					}
				}
			}
		}
		prevRegionStart = regionStart;
		regionStart = (ADDR)regionInfo.BaseAddress + regionInfo.RegionSize;
	}
	return matches;
}
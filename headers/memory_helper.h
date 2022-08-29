#pragma once
#include <pch.h>

using namespace std;

struct PatternFilter {
	char* assemblyCode;
	char* sameVals;
	unsigned int assemblyCodeSize;
	DWORD allocProtect;
	DWORD protect;
	DWORD type;
	DWORD state;
	DWORD size;
};

struct Region {
	ADDR start;
	SIZE_T size;
};

struct SearchArea {
	ADDR start;
	SIZE_T size;
};

class PatternMatcher {
public:
	DllExport PatternMatcher(SearchArea area) : area(area) {};
	DllExport PatternMatcher();
	DllExport PatternMatcher(HMODULE mod);
	DllExport vector<ADDR> findMatches(PatternFilter filter);
	DllExport SearchArea getSearchArea();
private:
	SearchArea area;
	vector<Region> findCandidateRegions(PatternFilter filter);
};
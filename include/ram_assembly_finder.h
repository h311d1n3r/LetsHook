#pragma once
#include "windows.h"
#include "ram_region_finder.h"
#include <string>
#define DllExport __declspec(dllexport)

DllExport struct ASSEMBLY_SEARCH_DATA {
	MEMORY_BASIC_INFORMATION region;
	char* assembly;
	int assemblyLen;
};

DllExport DWORDLONG findAssemblyInRegion(ASSEMBLY_SEARCH_DATA data);
DllExport DWORDLONG findSymbolAddressFromName(std::string symbolName);
DllExport DWORDLONG findAddress(REGION_SEARCH_DATA region_data, const char assembly[]);
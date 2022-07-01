#pragma once
#include <pch.h>

using namespace std;
using namespace asmjit::x86;

struct Hook {
	ADDR hookedAddr;
	ADDR hookAddr;
};

class HookInjector {
public:
	DllExport HookInjector(ADDR hookedAddr, ADDR hookAddr);
	DllExport HookInjector(string hookedName, ADDR hookAddr);
	DllExport void inject();
private:
	Hook hook;
#if DEBUG
	void printHook();
#endif
	bool isInjectable();
	ADDR findSymbolAddressFromName(string symbolName);
	void grantRights(LPVOID, SIZE_T);
	void injectInstructions(ADDR, vector<unsigned char>);
	MEMORY_BASIC_INFORMATION queryRegionInfo(LPCVOID);
	void prepareRegion(LPCVOID);
};
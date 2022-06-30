#pragma once
#include <pch.h>

using namespace std;
using namespace asmjit::x86;

struct Hook {
	ADDR addr;
	int codeLen;
	void* hookFunc;
};

class HookInjector {
public:
	DllExport HookInjector(ADDR addr, int codeLen, void* hookFunc);
	DllExport HookInjector(string symbolName, int codeLen, void* hookFunc);
	DllExport void inject();
private:
	Hook hook;
#if DEBUG
	void printHook();
#endif
	bool isInjectable();
	ADDR findSymbolAddressFromName(string symbolName);
	ADDR injectHookCall();
	void injectAllocJmp(ADDR);
	ADDR allocateMemory(SIZE_T);
	void grantRights(LPVOID, SIZE_T);
	void injectInstructions(ADDR, vector<unsigned char>);
	MEMORY_BASIC_INFORMATION queryRegionInfo(LPCVOID);
	void prepareRegion(LPCVOID);
};
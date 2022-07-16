#pragma once
#include <pch.h>

using namespace std;
using namespace asmjit::x86;

struct Hook {
	ADDR hookedAddr;
	ADDR hookAddr;
};

struct HookPatch {
	SIZE_T funcOff;
	vector<unsigned char> instructions;
	SIZE_T replacedLen;
};

class HookInjector {
public:
	Hook hook;
	DllExport HookInjector(ADDR hookedAddr, ADDR hookAddr);
	DllExport HookInjector(string hookedName, ADDR hookAddr);
	DllExport Func makeFunc(SIZE_T symLen, vector<HookPatch> patches);
	DllExport Func makeFunc(SIZE_T symLen) { return this->makeFunc(symLen, vector<HookPatch>()); };
	DllExport void inject();
private:
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
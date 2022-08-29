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
	DllExport ADDR makeFunc(SIZE_T symLen, vector<HookPatch> patches);
	DllExport ADDR makeFunc(SIZE_T symLen) { return this->makeFunc(symLen, vector<HookPatch>()); };
	DllExport void inject();
private:
#if DEBUG
	void printHook();
#endif
	BOOL isInjectable();
	ADDR findSymbolAddressFromName(string symbolName);
	void injectInstructions(ADDR, vector<unsigned char>);
	void prepareRegion(LPCVOID);
};
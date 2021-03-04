#pragma once
#include <string>
#include <windows.h>
#define DllExport __declspec(dllexport)

using namespace std;

struct Hook {
	SIZE_T addr;
	int codeLen;
	void* hookFunc;
};

class HookInjector {
public:
	DllExport HookInjector(SIZE_T addr, int codeLen, void* hookFunc);
	DllExport HookInjector(string, SIZE_T, int, void*);
	DllExport HookInjector(string symbolName, int codeLen, void* hookFunc) : HookInjector(symbolName, 0x0, codeLen, hookFunc) {};
	DllExport void inject();
private:
	Hook hook;
	void printHook();
	bool isInjectable();
	SIZE_T injectHookCall();
	void injectAllocJmp(SIZE_T);
	DWORD_PTR allocateMemory(SIZE_T);
	void grantRights(LPVOID, SIZE_T);
	void injectInstructions(SIZE_T, char*, SIZE_T);
	MEMORY_BASIC_INFORMATION queryRegionInfo(LPCVOID);
	void prepareRegion(LPCVOID);
};
#include "pch.h"
#include "hook.h"

HANDLE HookInjector::process;

HookInjector::HookInjector(string symbolName, int codeLen, void* hookFunc) {
	SYMBOL_INFO symInfo = {};
	symInfo.SizeOfStruct = sizeof(symInfo);
	symInfo.MaxNameLen = MAX_SYM_NAME;
	if (SymFromName(process, (PCSTR)symbolName.c_str(), &symInfo)) {
		this->hook = { symInfo.Address, codeLen, hookFunc };
	} else this->hook = { NULL, NULL };
}

void HookInjector::inject() {
	this->prepareRegion((LPCVOID)this->hook.addr);
	SIZE_T allocBase = this->injectHookCall();
	this->injectAllocJmp(allocBase);
}

SIZE_T HookInjector::injectHookCall() {
	char* hookFuncAddr = (char*)&(this->hook.hookFunc);
	int codeLen = this->hook.codeLen;
	char* assemblyCopy = (char*) malloc(codeLen);
	if (assemblyCopy) {
		for (int i = 0; i < codeLen; i++) {
			assemblyCopy[i] = *reinterpret_cast<char*>(this->hook.addr + i);
		}
	}
	const char call[] = {
		0x55, //push rbp
		0x48,0xbd,hookFuncAddr[0],hookFuncAddr[1],hookFuncAddr[2],hookFuncAddr[3],hookFuncAddr[4],hookFuncAddr[5],hookFuncAddr[6],hookFuncAddr[7], //mov rbp, 0xXXXXXXXXXXXXXXXX
		0xff, 0xd5, // call rbp
		0x5d //pop rbp
	};
	SIZE_T jmpBackAddr = this->hook.addr + sizeof(call);
	char* jmpBackArr = (char*)&jmpBackAddr;
	const char jmpBack[] = {
		0xff, 0x25, 0x0, 0x0, 0x0, 0x0,
		jmpBackArr[0],jmpBackArr[1],jmpBackArr[2],jmpBackArr[3],jmpBackArr[4],jmpBackArr[5],jmpBackArr[6],jmpBackArr[7] //jmp 0xXXXXXXXXXXXXXXXX
	};
	DWORD_PTR allocBase = this->allocateMemory(sizeof(call)+codeLen+sizeof(jmpBack));
	this->prepareRegion((LPCVOID)allocBase);
	this->injectInstructions(allocBase, (char*)call, sizeof(call));
	this->injectInstructions(allocBase + sizeof(call), assemblyCopy, codeLen);
	this->injectInstructions(allocBase + sizeof(call) + codeLen, (char*)jmpBack, sizeof(jmpBack));
	return allocBase;
}

void HookInjector::injectAllocJmp(SIZE_T allocBase) {
	char* allocBaseAddr = (char*)&(allocBase);
	const char jmp[] = {
		0xff, 0x25, 0x0, 0x0, 0x0, 0x0,
		allocBaseAddr[0],allocBaseAddr[1],allocBaseAddr[2],allocBaseAddr[3],allocBaseAddr[4],allocBaseAddr[5],allocBaseAddr[6],allocBaseAddr[7] //jmp 0xXXXXXXXXXXXXXXXX
	};
	int nopLen = this->hook.codeLen - sizeof(jmp);
	char* nopArr = (char*) malloc(nopLen);
	if (nopArr) {
		for (int i(0); i < nopLen; i++) {
			nopArr[i] = 0x90;
		}
		this->injectInstructions(this->hook.addr, (char*)jmp, sizeof(jmp));
		this->injectInstructions(this->hook.addr + sizeof(jmp), nopArr, nopLen);
	}
}

DWORD_PTR HookInjector::allocateMemory(SIZE_T size) {
	return reinterpret_cast<DWORD_PTR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size));
}

void HookInjector::grantRights(LPVOID regionBase, SIZE_T regionSize) {
	DWORD oldProtect;
	VirtualProtect(regionBase, regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
}

void HookInjector::injectInstructions(SIZE_T startAddr, char* instructions, SIZE_T instructionsLen) {
	char* target_ptr;
	for (int i(0); i < instructionsLen; i++) {
		target_ptr = reinterpret_cast<char*>(startAddr + i);
		*target_ptr = instructions[i];
	}
}

MEMORY_BASIC_INFORMATION HookInjector::queryRegionInfo(LPCVOID addr) {
	MEMORY_BASIC_INFORMATION regionInfo;
	VirtualQuery(addr, &regionInfo, sizeof(regionInfo));
	return regionInfo;
}

void HookInjector::prepareRegion(LPCVOID addr) {
	MEMORY_BASIC_INFORMATION regionInfo = this->queryRegionInfo(addr);
	this->grantRights(regionInfo.BaseAddress, regionInfo.RegionSize);
}
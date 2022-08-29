#include <pch.h>
#include <hook.h>
#include <TCHAR.h>
#include <algorithm>
#if DEBUG
#include <iostream>
#endif

HookInjector::HookInjector(ADDR hookedAddr, ADDR hookAddr) : hook{ hookedAddr, hookAddr } {
#if DEBUG
	this->printHook();
#endif
}

HookInjector::HookInjector(string hookedName, ADDR hookAddr) {
	ADDR hookedAddr = this->findSymbolAddressFromName(hookedName);
	this->hook = { hookedAddr, hookAddr };
#if DEBUG
	this->printHook();
#endif
}

ADDR HookInjector::findSymbolAddressFromName(string symbolName) {
	TCHAR szSymbolName[MAX_SYM_NAME];
	ULONG64 buffer[(sizeof(SYMBOL_INFO) +
		MAX_SYM_NAME * sizeof(TCHAR) +
		sizeof(ULONG64) - 1) /
		sizeof(ULONG64)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	_tcscpy_s(szSymbolName, MAX_SYM_NAME, (PCSTR)symbolName.c_str());
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	if (SymFromName(GetCurrentProcess(), szSymbolName, pSymbol)) return pSymbol->Address;
	return NULL;
}

#if DEBUG
void HookInjector::printHook() {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 13);
	cout << "Hook : { " << hex << this->hook.hookedAddr << ", " << (SIZE_T)this->hook.hookAddr << " }" << endl;
	SetConsoleTextAttribute(hConsole, 15);
}
#endif

BOOL HookInjector::isInjectable() {
	if (this->hook.hookedAddr && this->hook.hookAddr) {
		return TRUE;
	}
	#if DEBUG
	else {
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(hConsole, 12);
		if(!(this->hook.hookedAddr)) cout << "Can't inject hook... Address of hooked function is null" << endl;
		else cout << "Can't inject hook... Address of hook function is null" << endl;
		SetConsoleTextAttribute(hConsole, 15);
	}
	#endif
	return FALSE;
}

BOOL compareOffsets(HookPatch p1, HookPatch p2) {
	return p1.funcOff < p2.funcOff;
}

ADDR HookInjector::makeFunc(SIZE_T symLen, vector<HookPatch> patches) {
	SIZE_T effectiveLen = symLen;
	sort(patches.begin(), patches.end(), compareOffsets);
	for (HookPatch patch : patches) {
		SIZE_T instrLen = patch.instructions.size();
		effectiveLen += instrLen - patch.replacedLen;
	}
	ADDR allocAddr = (ADDR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, effectiveLen);
	if (allocAddr) {
		this->prepareRegion((LPCVOID)allocAddr);
		SIZE_T srcOff = 0;
		SIZE_T destOff = 0;
		for (HookPatch patch : patches) {
			memcpy((char*)allocAddr + destOff, (char*)this->hook.hookedAddr + srcOff, patch.funcOff - srcOff);
			destOff += patch.funcOff - destOff;
			srcOff += patch.funcOff - srcOff;
			memcpy((char*)allocAddr + destOff, patch.instructions.data(), patch.instructions.size());
			srcOff += patch.replacedLen;
			destOff += patch.instructions.size();
		}
		if(symLen > srcOff) memcpy((char*)allocAddr + destOff, (char*)this->hook.hookedAddr + srcOff, symLen - srcOff + 1);
#if DEBUG
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(hConsole, 13);
		cout << " Copy allocated at address : " << hex << +allocAddr << endl;
		SetConsoleTextAttribute(hConsole, 15);
#endif
		return allocAddr;
	}
	return NULL;
}

void HookInjector::inject() {
	if (!this->isInjectable()) return;

	this->prepareRegion((LPCVOID)this->hook.hookedAddr);
#if DEBUG
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 13);
	cout << " Region prepared !" << endl;
	SetConsoleTextAttribute(hConsole, 15);
#endif

	asmjit::JitRuntime rt;
	asmjit::CodeHolder code;
	code.init(rt.environment());
	Assembler a(&code);

	a.mov(rax, this->hook.hookAddr);
	a.jmp(rax);

	vector<unsigned char> codeVec(a.bufferData(), a.bufferPtr());
	this->injectInstructions(this->hook.hookedAddr, codeVec);

#if DEBUG
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 13);
	cout << " Hook call injected !" << endl;
	SetConsoleTextAttribute(hConsole, 15);
#endif
}

void HookInjector::injectInstructions(ADDR startAddr, vector<unsigned char> instructions) {
	char* target_ptr;
	for (int i(0); i < instructions.size(); i++) {
		target_ptr = reinterpret_cast<char*>(startAddr + i);
		*target_ptr = instructions[i];
	}
}

void HookInjector::prepareRegion(LPCVOID addr) {
	MEMORY_BASIC_INFORMATION regionInfo;
	VirtualQuery(addr, &regionInfo, sizeof(regionInfo));
	DWORD oldProtect;
	VirtualProtect(regionInfo.BaseAddress, regionInfo.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
}
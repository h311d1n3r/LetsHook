#include <pch.h>
#include <hook.h>
#include <TCHAR.h>
#if DEBUG
#include <iostream>
#endif

HookInjector::HookInjector(ADDR addr, int codeLen, void* hookFunc) : hook{ addr, codeLen, hookFunc } {
#if DEBUG
	this->printHook();
#endif
}

HookInjector::HookInjector(string symbolName, int codeLen, void* hookFunc) {
	ADDR symbolAddr = this->findSymbolAddressFromName(symbolName);
	this->hook = { symbolAddr, codeLen, hookFunc };
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
	cout << "Hook : { " << hex << this->hook.addr << ", 0x" << this->hook.codeLen << ", " << (SIZE_T)this->hook.hookFunc << " }" << endl;
	SetConsoleTextAttribute(hConsole, 8);
}
#endif

bool HookInjector::isInjectable() {
	if (this->hook.addr && this->hook.hookFunc) {
		if (this->hook.codeLen >= 13) {
			return true;
		}
		#if DEBUG
		else {
			HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
			SetConsoleTextAttribute(hConsole, 12);
			cout << "Can't inject hook... Assembly code to replace must have a length >= 13" << endl;
			SetConsoleTextAttribute(hConsole, 8);
		}
		#endif
	}
	#if DEBUG
	else {
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(hConsole, 12);
		if(!(this->hook.addr)) cout << "Can't inject hook... Address of assembly code to replace is null" << endl;
		else cout << "Can't inject hook... Hook function is null" << endl;
		SetConsoleTextAttribute(hConsole, 8);
	}
	#endif
	return false;
}

void HookInjector::inject() {
	if (!this->isInjectable()) return;
	this->prepareRegion((LPCVOID)this->hook.addr);
	#if DEBUG
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 13);
	cout << " Region prepared !" << endl;
	SetConsoleTextAttribute(hConsole, 8);
	#endif
	SIZE_T allocBase = this->injectHookCall();
	#if DEBUG
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 13);
	cout << " Hook call injected !" << endl;
	SetConsoleTextAttribute(hConsole, 8);
	#endif
	this->injectAllocJmp(allocBase);
	#if DEBUG
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 13);
	cout << " Alloc jmp injected !" << endl;
	SetConsoleTextAttribute(hConsole, 8);
	cout << endl;
	#endif
}

ADDR HookInjector::injectHookCall() {
	ADDR hookFuncAddr = (ADDR)(this->hook.hookFunc);
	int codeLen = this->hook.codeLen;

	asmjit::JitRuntime rt;
	asmjit::CodeHolder code;
	code.init(rt.environment());
	Assembler a(&code);

	a.pop(rax);
	a.push(rax);
	a.call(5);
	a.pop(rax);
	a.add(rax, 27);
	a.push(rax);
	a.movabs(rax, hookFuncAddr);
	a.push(rax);
	a.add(rsp, 0x10);
	a.pop(rax);
	a.sub(rsp, 0x18);
	a.ret(); //calls hook
	a.add(rsp, 0x8);
	for (int i = 0; i < codeLen; i++) {
		a.db(*reinterpret_cast<char*>(this->hook.addr + i));
	}
	a.push(rax);
	a.push(rax);
	a.mov(rax, this->hook.addr + codeLen);
	a.add(rsp, 0x10);
	a.push(rax);
	a.sub(rsp, 0x8);
	a.pop(rax);
	a.ret();

	vector<unsigned char> codeVec(a.bufferData(), a.bufferPtr());
	ADDR allocBase = this->allocateMemory(codeVec.size());
	this->prepareRegion((LPCVOID)allocBase);
	this->injectInstructions(allocBase, codeVec);
	return allocBase;
}

void HookInjector::injectAllocJmp(ADDR allocBase) {
	ADDR allocBaseAddr = (ADDR)&(allocBase);
	asmjit::JitRuntime rt;
	asmjit::CodeHolder code;
	code.init(rt.environment());
	Assembler a(&code);
	a.push(rax);
	a.mov(rax, allocBase);
	a.jmp(rax);
	int nopLen = this->hook.codeLen - 13;
	for (int i(0); i < nopLen; i++) {
		a.nop();
	}
	vector<unsigned char> codeVec(a.bufferData(), a.bufferPtr());
	this->injectInstructions(this->hook.addr, codeVec);
}

ADDR HookInjector::allocateMemory(SIZE_T size) {
	return reinterpret_cast<ADDR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size));
}

void HookInjector::grantRights(LPVOID regionBase, SIZE_T regionSize) {
	DWORD oldProtect;
	VirtualProtect(regionBase, regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
}

void HookInjector::injectInstructions(ADDR startAddr, vector<unsigned char> instructions) {
	char* target_ptr;
	for (int i(0); i < instructions.size(); i++) {
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
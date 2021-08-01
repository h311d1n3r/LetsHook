#include "pch.h"
#include "hook.h"
#include "assembler.h"
#include "ram_assembly_finder.h"
#ifdef DBG
#include <iostream>
#endif

HookInjector::HookInjector(SIZE_T addr, int codeLen, void* hookFunc) : hook{ addr, codeLen, hookFunc } {
	this->printHook();
}

HookInjector::HookInjector(string symbolName, SIZE_T off, int codeLen, void* hookFunc) {
	DWORDLONG addr;
	if(addr = findSymbolAddressFromName(symbolName)) {
		this->hook = { static_cast<SIZE_T>(addr+off), codeLen, hookFunc };
	} this->hook = {};
	this->printHook();
}

void HookInjector::printHook() {
	#ifdef DBG
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 13);
	cout << "Hook : { " << hex << this->hook.addr << ", 0x" << this->hook.codeLen << ", " << (SIZE_T)this->hook.hookFunc << " }" << endl;
	SetConsoleTextAttribute(hConsole, 8);
	#endif
}

bool HookInjector::isInjectable() {
	if (this->hook.addr && this->hook.hookFunc) {
		if (this->hook.codeLen >= 14) {
			return true;
		}
		#ifdef DBG
		else {
			HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
			SetConsoleTextAttribute(hConsole, 12);
			cout << "Can't inject hook... Assembly code to replace must have a length >= 14" << endl;
			SetConsoleTextAttribute(hConsole, 8);
		}
		#endif
	}
	#ifdef DBG
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
	#ifdef DBG
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 13);
	cout << " Region prepared !" << endl;
	SetConsoleTextAttribute(hConsole, 8);
	#endif
	SIZE_T allocBase = this->injectHookCall();
	#ifdef DBG
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 13);
	cout << " Hook call injected !" << endl;
	SetConsoleTextAttribute(hConsole, 8);
	#endif
	this->injectAllocJmp(allocBase);
	#ifdef DBG
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 13);
	cout << " Alloc jmp injected !" << endl;
	SetConsoleTextAttribute(hConsole, 8);
	cout << endl;
	#endif
}

SIZE_T HookInjector::injectHookCall() {
	char* hookFuncAddr = (char*)&(this->hook.hookFunc);
	int codeLen = this->hook.codeLen;

	string hookCallCode = Assembler::addChar(Register::RSP, 0x28);

	Register main_reg_push_routine[]{
	Register::R9,
	Register::R8,
	Register::RDX,
	Register::RCX
	};

	hookCallCode.append(Assembler::pushs(main_reg_push_routine, 4));
	hookCallCode.append(Assembler::subChar(Register::RSP, 0x8));
	hookCallCode.append(Assembler::subInt(Register::RSP, 0x100)); //secure function parameters

	Register func_reg_push_routine[]{
	Register::RAX,
	Register::RBX,
	Register::R10,
	Register::R11,
	Register::RBP
	};

	hookCallCode.append(Assembler::pushs(func_reg_push_routine, 5));
	hookCallCode.append(Assembler::mov(Register::RCX, Register::RSP));
	hookCallCode.append(Assembler::addInt(Register::RCX, 0x130)); //rcx now holds stack starting at rcx home
	hookCallCode.append(Assembler::subChar(Register::RSP, 0x50)); //secure push routine

	string call = {
		0x48,(char)0xbd,hookFuncAddr[0],hookFuncAddr[1],hookFuncAddr[2],hookFuncAddr[3],hookFuncAddr[4],hookFuncAddr[5],hookFuncAddr[6],hookFuncAddr[7], //mov rbp, 0xXXXXXXXXXXXXXXXX
		(char)0xff, (char)0xd5, // call rbp
	};

	hookCallCode.append(call);
	hookCallCode.append(Assembler::addChar(Register::RSP, 0x50));

	Register func_reg_pop_routine[]{
	Register::RBP,
	Register::R11,
	Register::R10,
	Register::RBX,
	Register::RAX
	};

	hookCallCode.append(Assembler::pops(func_reg_pop_routine, 5));
	hookCallCode.append(Assembler::addInt(Register::RSP, 0x108));
	hookCallCode.append(Assembler::movSrcPtr(Register::RCX, Register::RSP));
	hookCallCode.append(Assembler::addChar(Register::RSP, 0x8));
	hookCallCode.append(Assembler::movSrcPtr(Register::RDX, Register::RSP));
	hookCallCode.append(Assembler::addChar(Register::RSP, 0x8));
	hookCallCode.append(Assembler::movSrcPtr(Register::R8, Register::RSP));
	hookCallCode.append(Assembler::addChar(Register::RSP, 0x8));
	hookCallCode.append(Assembler::movSrcPtr(Register::R9, Register::RSP));
	hookCallCode.append(Assembler::subChar(Register::RSP, 0x20));

	string assemblyCopy = "";
	for (int i = 0; i < codeLen; i++) {
		assemblyCopy.push_back(*reinterpret_cast<char*>(this->hook.addr + i));
	}

	hookCallCode.append(assemblyCopy);

	SIZE_T jmpBackAddr = this->hook.addr + 0xe; //0xe -> jmp length
	char* jmpBackArr = (char*)&jmpBackAddr;
	string jmpBack = {
		(char)0xff, 0x25, 0x0, 0x0, 0x0, 0x0,
		jmpBackArr[0],jmpBackArr[1],jmpBackArr[2],jmpBackArr[3],jmpBackArr[4],jmpBackArr[5],jmpBackArr[6],jmpBackArr[7] //jmp 0xXXXXXXXXXXXXXXXX
	};

	hookCallCode.append(jmpBack);

	DWORD_PTR allocBase = this->allocateMemory(hookCallCode.size());
	this->prepareRegion((LPCVOID)allocBase);
	this->injectInstructions(allocBase, (char*)hookCallCode.c_str(), hookCallCode.size());
	return allocBase;
}

void HookInjector::injectAllocJmp(SIZE_T allocBase) {
	char* allocBaseAddr = (char*)&(allocBase);
	const char jmp[] = {
		static_cast<const char>(0xff), 0x25, 0x0, 0x0, 0x0, 0x0,
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
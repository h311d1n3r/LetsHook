#include "pch.h"
#include "hook.h"
#include "assembler.h"
#ifdef DBG
#include <iostream>
#endif

HANDLE HookInjector::process;

HookInjector::HookInjector(string symbolName, SIZE_T off, int codeLen, void* hookFunc) {
	SYMBOL_INFO symInfo = { };
	symInfo.SizeOfStruct = sizeof(symInfo);
	symInfo.MaxNameLen = MAX_SYM_NAME;
	if (SymFromName(process, (PCSTR)symbolName.c_str(), &symInfo)) {
		this->hook = { symInfo.Address+off, codeLen, hookFunc };
	} else this->hook = { NULL, NULL, NULL };
	#ifdef DBG
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 13);
	cout << "Hook : { " << hex << this->hook.addr << ", 0x" << this->hook.codeLen << ", " << (SIZE_T)this->hook.hookFunc << " }" << endl;
	SetConsoleTextAttribute(hConsole, 15);
	#endif
}

void HookInjector::inject() {
	this->prepareRegion((LPCVOID)this->hook.addr);
	#ifdef DBG
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 10);
	cout << " Region prepared !" << endl;
	SetConsoleTextAttribute(hConsole, 15);
	#endif
	SIZE_T allocBase = this->injectHookCall();
	#ifdef DBG
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 10);
	cout << " Hook call injected !" << endl;
	SetConsoleTextAttribute(hConsole, 15);
	#endif
	this->injectAllocJmp(allocBase);
	#ifdef DBG
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 10);
	cout << " Alloc jmp injected !" << endl;
	SetConsoleTextAttribute(hConsole, 15);
	cout << endl;
	#endif
}

SIZE_T HookInjector::injectHookCall() {
	char* hookFuncAddr = (char*)&(this->hook.hookFunc);
	int codeLen = this->hook.codeLen;

	string addRsp = Assembler::addChar(Register::RSP, 0x28);
	Register main_reg_push_routine[]{
	Register::R9,
	Register::R8,
	Register::RDX,
	Register::RCX
	};
	string main_reg_pushs = Assembler::pushs(main_reg_push_routine, 4);

	string fixRsp = Assembler::subChar(Register::RSP, 0x8);

	string subRsp = Assembler::subInt(Register::RSP, 0x100); //secure function parameters

	Register push_routine[]{
	Register::RAX,
	Register::RBX,
	Register::R10,
	Register::R11,
	Register::RBP
	};
	string pushs = Assembler::pushs(push_routine, 5);

	string movRsp = Assembler::mov(Register::RCX, Register::RSP);

	string addRcx = Assembler::addInt(Register::RCX, 0x130); //rcx now holds stack starting at rcx home

	string subRsp2 = Assembler::subChar(Register::RSP, 0x50); //secure push routine

	string call = {
		0x48,(char)0xbd,hookFuncAddr[0],hookFuncAddr[1],hookFuncAddr[2],hookFuncAddr[3],hookFuncAddr[4],hookFuncAddr[5],hookFuncAddr[6],hookFuncAddr[7], //mov rbp, 0xXXXXXXXXXXXXXXXX
		(char)0xff, (char)0xd5, // call rbp
	};

	string addRsp2 = Assembler::addChar(Register::RSP, 0x50);

	Register pop_routine[]{
	Register::RBP,
	Register::R11,
	Register::R10,
	Register::RBX,
	Register::RAX
	};
	string pops = Assembler::pops(pop_routine, 5);

	string addRsp3 = Assembler::addInt(Register::RSP, 0x108);

	string movRcx = Assembler::movSrcPtr(Register::RCX, Register::RSP);
	string addRsp4 = Assembler::addChar(Register::RSP, 0x8);
	string movRdx = Assembler::movSrcPtr(Register::RDX, Register::RSP);
	//addRsp4
	string movR8 = Assembler::movSrcPtr(Register::R8, Register::RSP);
	//addRsp4
	string movR9 = Assembler::movSrcPtr(Register::R9, Register::RSP);

	string subRsp3 = Assembler::subChar(Register::RSP, 0x20);

	string assemblyCopy = "";
	for (int i = 0; i < codeLen; i++) {
		assemblyCopy.push_back(*reinterpret_cast<char*>(this->hook.addr + i));
	}

	SIZE_T jmpBackAddr = this->hook.addr + 0xe; //0xe -> jmp length
	char* jmpBackArr = (char*)&jmpBackAddr;
	string jmpBack = {
		(char)0xff, 0x25, 0x0, 0x0, 0x0, 0x0,
		jmpBackArr[0],jmpBackArr[1],jmpBackArr[2],jmpBackArr[3],jmpBackArr[4],jmpBackArr[5],jmpBackArr[6],jmpBackArr[7] //jmp 0xXXXXXXXXXXXXXXXX
	};

	string hookCallCode = addRsp;
	hookCallCode.append(main_reg_pushs);
	hookCallCode.append(fixRsp);
	hookCallCode.append(subRsp);
	hookCallCode.append(pushs);
	hookCallCode.append(movRsp);
	hookCallCode.append(addRcx);
	hookCallCode.append(subRsp2);
	hookCallCode.append(call);
	hookCallCode.append(addRsp2);
	hookCallCode.append(pops);
	hookCallCode.append(addRsp3);
	hookCallCode.append(movRcx);
	hookCallCode.append(addRsp4);
	hookCallCode.append(movRdx);
	hookCallCode.append(addRsp4);
	hookCallCode.append(movR8);
	hookCallCode.append(addRsp4);
	hookCallCode.append(movR9);
	hookCallCode.append(subRsp3);
	hookCallCode.append(assemblyCopy);
	hookCallCode.append(jmpBack);

	DWORD_PTR allocBase = this->allocateMemory(hookCallCode.size());
	this->prepareRegion((LPCVOID)allocBase);
	this->injectInstructions(allocBase, (char*)hookCallCode.c_str(), hookCallCode.size());
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
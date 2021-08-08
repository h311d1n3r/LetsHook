#include "breakpoint.h"

using namespace std;

bool BreakpointInjector::sendBreakpoint(DWORDLONG addr, string name, bool keepBp) {
	REGISTERS registers = {};
	const char breakPointArr[] = { BREAKPOINT };
	char* addrArr = (char*)&addr;
	pipe->sendData((char*)breakPointArr, sizeof(breakPointArr));
	pipe->sendData(addrArr, sizeof(DWORDLONG));
	pipe->sendData((char*)name.c_str(), name.length());
	const char keepBpArr[] = { keepBp };
	pipe->sendData((char*)keepBpArr, sizeof(keepBpArr));
	char msg[BUFF_LEN];
	while (pipe->readData(msg) <= 0) Sleep(100);
	if (msg) {
		if (msg[0] == BREAKPOINT) return true;
	}
	return false;
}

BREAKPOINT_RESULT BreakpointInjector::readBreakpointResult() {
	REGISTERS registers = {};
	string name;
	char msg[BUFF_LEN];
	while (pipe->readData(msg) <= 0) Sleep(100);
	if (msg) {
		if (msg[0] == BREAKPOINT) {
			int nameLen = pipe->readData(msg);
			name = string((const char*) msg, nameLen);
			for (int i = 0; i < sizeof(REGISTERS) / sizeof(DWORD64); i++) {
				if (pipe->readData(msg) == sizeof(DWORD64)) {
					switch (i) {
					case 0:
						memcpy(&(registers.RAX), msg, sizeof(DWORD64));
						break;
					case 1:
						memcpy(&(registers.RBX), msg, sizeof(DWORD64));
						break;
					case 2:
						memcpy(&(registers.RCX), msg, sizeof(DWORD64));
						break;
					case 3:
						memcpy(&(registers.RDX), msg, sizeof(DWORD64));
						break;
					case 4:
						memcpy(&(registers.R8), msg, sizeof(DWORD64));
						break;
					case 5:
						memcpy(&(registers.R9), msg, sizeof(DWORD64));
						break;
					case 6:
						memcpy(&(registers.R10), msg, sizeof(DWORD64));
						break;
					case 7:
						memcpy(&(registers.R11), msg, sizeof(DWORD64));
						break;
					case 8:
						memcpy(&(registers.R12), msg, sizeof(DWORD64));
						break;
					case 9:
						memcpy(&(registers.R13), msg, sizeof(DWORD64));
						break;
					case 10:
						memcpy(&(registers.R14), msg, sizeof(DWORD64));
						break;
					case 11:
						memcpy(&(registers.R15), msg, sizeof(DWORD64));
						break;
					case 12:
						memcpy(&(registers.RDI), msg, sizeof(DWORD64));
						break;
					case 13:
						memcpy(&(registers.RSI), msg, sizeof(DWORD64));
						break;
					case 14:
						memcpy(&(registers.RSP), msg, sizeof(DWORD64));
						break;
					}
				}
			}
		}
	}
	return { name, registers };
}

void BreakpointInjector::startDebugger() {
	const char startDbgArr[] = { START_DEBUGGER };
	pipe->sendData((char*)startDbgArr, sizeof(startDbgArr));
}
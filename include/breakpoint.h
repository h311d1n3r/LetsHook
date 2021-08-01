#pragma once
#include <pipe_client.h>
#include <string>
#define DllExport __declspec(dllexport)

struct BREAKPOINT_RESULT {
	std::string name;
	REGISTERS regs;
};

class BreakpointInjector {
public:
	inline static PipeClient* pipe = NULL;
	static DllExport bool sendBreakpoint(DWORDLONG addr, std::string name, const char replacedChar);
	static DllExport BREAKPOINT_RESULT readBreakpointResult();
	static DllExport void startDebugger();
};
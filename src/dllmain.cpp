#include "pch.h"
#include "hook.h"

const char* VERSION = "1.1";

void init() {
    #ifdef DBG
    RedirectIOToConsole();
    #endif
    HookInjector::process = GetCurrentProcess();
    SymInitialize(HookInjector::process, NULL, TRUE);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        init();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


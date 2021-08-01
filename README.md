# LetsHook
## Description
***LetsHook*** is a **Windows x64** library designed to easily hook functions in external processes after injection.
## Requirements
-Target processes must be **64 bits**.  
-You need a specific **DLL injector** to deploy both the library (before any hook) and the hooks you created. The injector will also act as a debugger and communicate through a pipe with the targeted process. You can find it here : [LetsHook Injector](https://github.com/h311d1n3r/LetsHook-Injector)  
## Coding
After compiling the repository code into both a **.DLL** and a **.LIB**, start a new DLL project and include the **.LIB** as well as the **header files**.  
You will want to include **hook.h** in you source files using `#include "hook.h"` and then instantiate a new `HookInjector` to call the `inject()` method.  
After your code is ready, **compile your DLL** and **inject it after the library DLL** into the target process.
## WARNING
The **HookInjector constructors** ask for a `codeLen` parameter. It represents **the exact amount of instruction bytes replaced at the start of the hooked method** so that no instruction get cut. **This value is minimum 14 !**
## Example
This code will hook `WSARecv(...)` method from `winsock2.h`.

```
#include "hook.h"
#include <string>
#include "winsock2.h"
#include <iostream>
[...]

void hookWSARecv(SIZE_T* stack) {
    SOCKET socket = stack[0];
    cout << socket << endl;
}

void initInjector() {
    HookInjector injector("WS2_32!WSARecv", 15, &hookWSARecv);
    injector.inject();
}
```

This code will set a breakpoint on `recv(...)` method from `winsock2.h`.

```
#include "breakpoint.h"
#include "ram_assembly_finder.h"
#include "winsock2.h"
#include <iostream>
[...]

void recvBreakpoint() {
    DWORDLONG recvAddr = findSymbolAddressFromName("WS2_32!recv");
    if (BreakpointInjector::sendBreakpoint(recvAddr, "recv_breakpoint", 0x48)) {
        BreakpointInjector::startDebugger();
        BREAKPOINT_RESULT result = BreakpointInjector::readBreakpointResult();
        if(!result.name.compare("recv_breakpoint")) {
            SOCKET socket = result.regs.RCX;
            cout << hex << socket << endl;
        }
    }
}
```

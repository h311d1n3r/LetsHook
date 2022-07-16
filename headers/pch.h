#include <windows.h>
#include <dbghelp.h>
#include <string>
#include <vector>
#include <asmjit/asmjit.h>

#pragma comment(lib, "Dbghelp.lib")

#define DllExport __declspec(dllexport)
#define ADDR DWORDLONG
typedef int (*Func)(...);
#pragma once
#include <windows.h>
#include <string>
#define DllExport __declspec(dllexport)

DllExport DWORDLONG findSymbolAddressFromName(std::string symbolName);
DllExport bool loadModuleSymbols(HANDLE process, std::string moduleName, PSYM_ENUMERATESYMBOLS_CALLBACK symbolCallback);
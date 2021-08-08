#include <pch.h>
#include <symbols.h>

using namespace std;

DWORDLONG findSymbolAddressFromName(string symbolName) {
	SYMBOL_INFO symInfo = { };
	symInfo.SizeOfStruct = sizeof(symInfo);
	symInfo.MaxNameLen = MAX_SYM_NAME;
	if (SymFromName(GetCurrentProcess(), (PCSTR)symbolName.c_str(), &symInfo)) return symInfo.Address;
	return NULL;
}

bool loadModuleSymbols(HANDLE process, string moduleName, PSYM_ENUMERATESYMBOLS_CALLBACK symbolCallback) {
	string upperModuleName = moduleName;
	for (auto& c : upperModuleName) c = toupper(c);
	string moduleNamePrefix = moduleName.substr(0, upperModuleName.find_last_of(".DLL") - 3);
	return SymEnumSymbols(process, NULL, (moduleNamePrefix+"!*").c_str(), symbolCallback, NULL);
}
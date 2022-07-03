VC_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\VC
MSVC_PATH=$(VC_PATH)\Tools\MSVC
MSVC_VERSION=$(shell ls "$(MSVC_PATH)")
WINKITS_PATH=C:\Program Files (x86)\Windows Kits
WIN_KITS_VERSION=$(shell ls "$(WINKITS_PATH)\10\Include")
VCVARSALL=$(VC_PATH)\Auxiliary\Build\vcvarsall.bat

UNIV_CRT_INC=$(WINKITS_PATH)\$(WIN_KITS_VERSION)\Include\$(MSVC_VERSION)\ucrt
UNIV_CRT_LIB=$(WINKITS_PATH)\$(WIN_KITS_VERSION)\Lib\$(MSVC_VERSION)\ucrt\x64

LETSHOOK_SRC=src
LETSHOOK_INC=headers

ASMJIT_PATH=lib/asmjit/src

CC="$(MSVC_PATH)\$(MSVC_VERSION)\bin\Hostx64\x64\cl"
COMPILE_FLAGS=-D_USRDLL -D_WINDLL -EHsc -std:c++17

PERCENT=%

bin/LetsHook.dll: prepare_env bin/lib/asmjit.dll
	@echo "Building LetsHook..."
	@$(CC) $(COMPILE_FLAGS) $(LETSHOOK_SRC)/*.cpp asmjit.lib -Foobj/ -I$(LETSHOOK_INC) -I$(ASMJIT_PATH) -I"$(INCLUDE)" -I"$(UNIV_CRT_INC)" -link -LIBPATH:"$(LIBPATH)" -LIBPATH:"bin\lib" -LIBPATH:"$(LIB)" -LIBPATH:"$(UNIV_CRT_LIB)" -dll -out:$@

bin/lib/asmjit.dll: prepare_env
	@echo "Building AsmJit..."
	@mkdir -p bin/lib
	@mkdir -p obj/asmjit/
	@$(CC) $(COMPILE_FLAGS) $(ASMJIT_PATH)/asmjit/**/*.cpp -Foobj/asmjit/ -I$(ASMJIT_PATH) -I"$(INCLUDE)" -I"$(UNIV_CRT_INC)" -link -LIBPATH:"$(LIBPATH)" -LIBPATH:"$(LIB)" -LIBPATH:"$(UNIV_CRT_LIB)" -dll -out:$@

.PHONY: clean	
clean:
	@echo "Cleaning repository..."
	rm -rf bin;
	rm -rf obj

.PHONY: prepare_env
prepare_env:
	@if [ ! -f "./lib/asmjit/CMakeLists.txt" ]; then\
		echo "Installing git submodules...";\
		git submodule init;\
		git submodule update;\
	fi
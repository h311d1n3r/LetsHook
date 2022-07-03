@SET VC_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\VC
@SET WINKITS_PATH=C:\Program Files (x86)\Windows Kits
@for /F "delims=" %%I in ('dir /b "%WINKITS_PATH%\10\Include"') do @SET WIN_KITS_VERSION=%%I
@SET VCVARSALL=%VC_PATH%\Auxiliary\Build\vcvarsall.bat
@call "%VCVARSALL%" x64 %WIN_KITS_VERSION% > nul
@echo export INCLUDE="%INCLUDE%" ^&^& export LIBPATH="%LIBPATH%" ^&^& export LIB="%LIB%"
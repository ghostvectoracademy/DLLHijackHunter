@echo off
REM Rebuild the embedded precompiled canaries from canary_src.c.
REM Requires an installed Windows SDK + MSVC C++ tools (a Build Tools install is enough).
REM /MT statically links the CRT so the canary has NO runtime dependency (ucrtbase/vcruntime)
REM on the victim host. After running, rebuild the scanner so the new DLLs get embedded.
setlocal
set VCVARS="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
cd /d "%~dp0"

echo === Building x64 ===
call %VCVARS% x64 >nul
cl /nologo /LD /O1 /MT /Fe:canary_x64.dll canary_src.c advapi32.lib kernel32.lib /link /DLL
if errorlevel 1 ( echo X64 BUILD FAILED & exit /b 1 )

endlocal
setlocal
set VCVARS="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
cd /d "%~dp0"

echo === Building x86 ===
call %VCVARS% x86 >nul
cl /nologo /LD /O1 /MT /Fe:canary_x86.dll canary_src.c advapi32.lib kernel32.lib /link /DLL
if errorlevel 1 ( echo X86 BUILD FAILED & exit /b 1 )

echo === Cleaning intermediates ===
del /q canary_src.obj canary_x64.exp canary_x64.lib canary_x86.exp canary_x86.lib 2>nul
echo === DONE ===

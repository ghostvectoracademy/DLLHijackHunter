:: canary/build_canary.bat
@echo off
echo Building canary DLL templates...

where gcc >nul 2>&1
if %errorlevel% equ 0 (
    echo Using GCC...
    gcc -shared -o canary_x64.dll canary_template.c -ladvapi32 -lkernel32
    gcc -shared -m32 -o canary_x86.dll canary_template.c -ladvapi32 -lkernel32
    echo Done.
) else (
    echo GCC not found. Canary DLLs will be compiled at runtime.
    echo Install MinGW-w64 or ensure cl.exe is in PATH.
)
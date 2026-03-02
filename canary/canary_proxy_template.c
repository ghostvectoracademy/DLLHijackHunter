// canary/canary_proxy_template.c
// Proxy DLL template — forwards all exports to the original DLL
// Export pragmas are generated dynamically by CanaryDllBuilder

#include <windows.h>
#include <stdio.h>
#include <time.h>

#ifndef CANARY_ID
#define CANARY_ID "DEFAULT_PROXY_CANARY"
#endif

#ifndef CONFIRM_DIR
#define CONFIRM_DIR "C:\\ProgramData\\DLLHijackHunter"
#endif

// Same WriteConfirmation as canary_template.c (included inline)
static void WriteConfirmation(void)
{
    CreateDirectoryA(CONFIRM_DIR, NULL);
    char confirmPath[MAX_PATH];
    snprintf(confirmPath, sizeof(confirmPath), "%s\\%s.confirm", CONFIRM_DIR, CANARY_ID);

    HANDLE hFile = CreateFileA(confirmPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    char buf[2048];
    char procPath[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, procPath, MAX_PATH);

    int len = snprintf(buf, sizeof(buf),
                       "CONFIRMED=TRUE\nCANARY_ID=%s\nPROCESS=%s\nPID=%lu\nTIMESTAMP=%lu\n",
                       CANARY_ID, procPath, GetCurrentProcessId(),
                       (unsigned long)time(NULL));

    DWORD written;
    WriteFile(hFile, buf, (DWORD)len, &written, NULL);
    CloseHandle(hFile);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        WriteConfirmation();
    }
    return TRUE;
}

// ═══════════════════════════════════════════════
// Export forwards are appended here by the build system.
// Example for version.dll:
//
// #pragma comment(linker, "/export:GetFileVersionInfoA=C:\\Windows\\System32\\version.GetFileVersionInfoA")
// #pragma comment(linker, "/export:GetFileVersionInfoW=C:\\Windows\\System32\\version.GetFileVersionInfoW")
// ... etc
// ═══════════════════════════════════════════════
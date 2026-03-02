// canary/canary_template.c
// Standalone canary DLL template — compile with MinGW or MSVC
// gcc -shared -o canary.dll canary_template.c -ladvapi32 -lkernel32

#include <windows.h>
#include <stdio.h>
#include <time.h>

// These are replaced at build time by the canary engine
#ifndef CANARY_ID
#define CANARY_ID "DEFAULT_CANARY"
#endif

#ifndef CONFIRM_DIR
#define CONFIRM_DIR "C:\\ProgramData\\DLLHijackHunter"
#endif

static void WriteConfirmation(void)
{
    CreateDirectoryA(CONFIRM_DIR, NULL);

    char confirmPath[MAX_PATH];
    snprintf(confirmPath, sizeof(confirmPath), "%s\\%s.confirm", CONFIRM_DIR, CANARY_ID);

    HANDLE hFile = CreateFileA(confirmPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    char buf[4096];
    char procPath[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, procPath, MAX_PATH);
    DWORD pid = GetCurrentProcessId();

    char username[256] = "UNKNOWN";
    char domain[256] = "";
    DWORD userLen = sizeof(username);
    DWORD domLen = sizeof(domain);
    const char *integrity = "Unknown";
    BOOL hasDebug = FALSE;

    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        BYTE tokenUser[512];
        DWORD retLen = 0;
        if (GetTokenInformation(hToken, TokenUser, tokenUser, sizeof(tokenUser), &retLen))
        {
            SID_NAME_USE sidType;
            LookupAccountSidA(NULL, ((TOKEN_USER *)tokenUser)->User.Sid,
                              username, &userLen, domain, &domLen, &sidType);
        }

        BYTE tokenIL[512];
        if (GetTokenInformation(hToken, TokenIntegrityLevel, tokenIL, sizeof(tokenIL), &retLen))
        {
            PDWORD pIL = GetSidSubAuthority(
                ((TOKEN_MANDATORY_LABEL *)tokenIL)->Label.Sid,
                *GetSidSubAuthorityCount(((TOKEN_MANDATORY_LABEL *)tokenIL)->Label.Sid) - 1);

            DWORD il = *pIL;
            if (il >= 0x4000)
                integrity = "System";
            else if (il >= 0x3000)
                integrity = "High";
            else if (il >= 0x2000)
                integrity = "Medium";
            else
                integrity = "Low";
        }

        LUID debugLuid;
        if (LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &debugLuid))
        {
            PRIVILEGE_SET privs;
            privs.PrivilegeCount = 1;
            privs.Control = 1;
            privs.Privilege[0].Luid = debugLuid;
            privs.Privilege[0].Attributes = 0;
            PrivilegeCheck(hToken, &privs, &hasDebug);
        }

        CloseHandle(hToken);
    }

    int len = snprintf(buf, sizeof(buf),
                       "CONFIRMED=TRUE\n"
                       "CANARY_ID=%s\n"
                       "PROCESS=%s\n"
                       "PID=%lu\n"
                       "USER=%s\\%s\n"
                       "INTEGRITY=%s\n"
                       "SE_DEBUG=%s\n"
                       "TIMESTAMP=%lu\n",
                       CANARY_ID, procPath, pid, domain, username,
                       integrity, hasDebug ? "YES" : "NO",
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
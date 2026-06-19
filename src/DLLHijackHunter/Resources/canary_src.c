/*
 * DLLHijackHunter — precompiled self-locating canary
 * ---------------------------------------------------
 * This source is compiled once to canary_x64.dll and canary_x86.dll, which are
 * embedded as resources in the scanner. Unlike the legacy per-run compiled
 * canary, it bakes in NOTHING about a specific run: when DllMain fires it
 * derives its confirmation-file path at runtime from its own loaded module path
 * so a single binary serves every candidate of a given architecture.
 *
 * Identity scheme (must stay byte-for-byte in sync with CanaryDllBuilder.cs):
 *   confirm dir  = %ProgramData%\DLLHijackHunter   (ALLUSERSPROFILE fallback)
 *   confirm file = canary_<fnv1a64(lowercased module path)>.confirm
 *
 * FNV-1a 64-bit over the ASCII module path, with A-Z folded to a-z. The scanner
 * computes the same hash from the path it deployed the canary to and polls for
 * the resulting file. ASCII paths only (System32/Program Files/temp); a non-ASCII
 * deploy path would hash differently on each side and simply not match.
 *
 * Build (from a developer prompt, or via vcvarsall):
 *   cl /LD /O1 /Fe:canary_x64.dll canary_src.c advapi32.lib kernel32.lib /link /DLL /NOLOGO
 */

#include <windows.h>
#include <stdio.h>
#include <time.h>

static unsigned long long fnv1a(const char *s)
{
    unsigned long long h = 0xcbf29ce484222325ULL;
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p)
    {
        unsigned char b = *p;
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b + 0x20);
        h ^= b;
        h *= 0x100000001b3ULL;
    }
    return h;
}

static void BuildConfirmDir(char *dir, size_t cap)
{
    char base[MAX_PATH] = {0};
    DWORD n = GetEnvironmentVariableA("ProgramData", base, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        n = GetEnvironmentVariableA("ALLUSERSPROFILE", base, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        lstrcpynA(base, "C:\\ProgramData", MAX_PATH);
    _snprintf_s(dir, cap, _TRUNCATE, "%s\\DLLHijackHunter", base);
}

static void WriteConfirmation(HMODULE hModule)
{
    char modPath[MAX_PATH] = {0};
    GetModuleFileNameA(hModule, modPath, MAX_PATH);

    char dir[MAX_PATH];
    BuildConfirmDir(dir, sizeof(dir));
    CreateDirectoryA(dir, NULL);

    char confirmPath[MAX_PATH];
    _snprintf_s(confirmPath, sizeof(confirmPath), _TRUNCATE,
                "%s\\canary_%016llx.confirm", dir, fnv1a(modPath));

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
    if (OpenProcessToken(GetCurrentProcess(), 0x0008 /*TOKEN_QUERY*/, &hToken))
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
            if (il >= 0x4000) integrity = "System";
            else if (il >= 0x3000) integrity = "High";
            else if (il >= 0x2000) integrity = "Medium";
            else integrity = "Low";
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

    int len = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "[DllHijackHunter] precompiled canary fired\n"
        "MODULE=%s\n"
        "PROCESS=%s\n"
        "PID=%lu\n"
        "USER=%s\\%s\n"
        "INTEGRITY=%s\n"
        "SE_DEBUG=%s\n"
        "TIMESTAMP=%lu\n",
        modPath, procPath, pid, domain, username,
        integrity, hasDebug ? "YES" : "NO",
        (unsigned long)time(NULL));

    DWORD written;
    WriteFile(hFile, buf, (DWORD)len, &written, NULL);
    CloseHandle(hFile);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    (void)lpReserved;
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        WriteConfirmation(hModule);
    }
    return TRUE;
}

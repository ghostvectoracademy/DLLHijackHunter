// src/DLLHijackHunter/Canary/CanaryDllBuilder.cs

using DLLHijackHunter.Discovery;

namespace DLLHijackHunter.Canary;

public static class CanaryDllBuilder
{
    private static readonly string CanaryDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "DLLHijackHunter");

    /// <summary>
    /// Build a canary DLL that writes a confirmation file when DllMain executes.
    /// </summary>
    public static CanaryDllInfo BuildCanary(string canaryId, string dllName,
        string? originalDllPath, bool is64Bit)
    {
        Directory.CreateDirectory(CanaryDir);

        string confirmPath = Path.Combine(CanaryDir, $"{canaryId}.confirm");
        string canaryDllPath = Path.Combine(CanaryDir, $"canary_{canaryId}.dll");

        // Generate C source for canary
        string source = GenerateCanarySource(canaryId, confirmPath, originalDllPath);

        // Write source file
        string sourcePath = Path.Combine(CanaryDir, $"canary_{canaryId}.c");
        File.WriteAllText(sourcePath, source);

        // Compile using available compiler
        bool compiled = CompileCanary(sourcePath, canaryDllPath, is64Bit, originalDllPath);

        if (!compiled)
        {
            // Fallback: PowerShell-based canary
            string psCanaryPath = BuildPowerShellCanary(canaryId, confirmPath);

            return new CanaryDllInfo
            {
                CanaryId = canaryId,
                DllPath = "", // empty — signals that DLL compilation failed
                ConfirmPath = confirmPath,
                SourcePath = sourcePath,
                IsProxy = originalDllPath != null,
                FallbackScript = psCanaryPath
            };
        }

        return new CanaryDllInfo
        {
            CanaryId = canaryId,
            DllPath = canaryDllPath,
            ConfirmPath = confirmPath,
            SourcePath = sourcePath,
            IsProxy = originalDllPath != null
        };
    }

    private static string GenerateCanarySource(string canaryId, string confirmPath,
        string? originalDllPath)
    {
        string escapedConfirmPath = confirmPath.Replace("\\", "\\\\");
        string escapedCanaryDir = CanaryDir.Replace("\\", "\\\\");

        var sb = new System.Text.StringBuilder();

        sb.AppendLine("#include <windows.h>");
        sb.AppendLine("#include <stdio.h>");
        sb.AppendLine("#include <time.h>");
        sb.AppendLine();
        sb.AppendLine($"#define CANARY_ID \"{canaryId}\"");
        sb.AppendLine($"#define CONFIRM_PATH \"{escapedConfirmPath}\"");
        sb.AppendLine($"#define CONFIRM_DIR \"{escapedCanaryDir}\"");
        sb.AppendLine();

        sb.AppendLine(@"
static void WriteConfirmation(void)
{
    CreateDirectoryA(CONFIRM_DIR, NULL);

    HANDLE hFile = CreateFileA(CONFIRM_PATH, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    char buf[4096];
    char procPath[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, procPath, MAX_PATH);
    DWORD pid = GetCurrentProcessId();

    char username[256] = ""UNKNOWN"";
    char domain[256] = """";
    DWORD userLen = sizeof(username);
    DWORD domLen = sizeof(domain);
    const char *integrity = ""Unknown"";
    BOOL hasDebug = FALSE;

    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), 0x0008, &hToken))
    {
        BYTE tokenUser[512];
        DWORD retLen = 0;
        if (GetTokenInformation(hToken, TokenUser, tokenUser, sizeof(tokenUser), &retLen))
        {
            SID_NAME_USE sidType;
            LookupAccountSidA(NULL, ((TOKEN_USER*)tokenUser)->User.Sid,
                            username, &userLen, domain, &domLen, &sidType);
        }

        BYTE tokenIL[512];
        if (GetTokenInformation(hToken, TokenIntegrityLevel, tokenIL, sizeof(tokenIL), &retLen))
        {
            PDWORD pIL = GetSidSubAuthority(
                ((TOKEN_MANDATORY_LABEL*)tokenIL)->Label.Sid,
                *GetSidSubAuthorityCount(((TOKEN_MANDATORY_LABEL*)tokenIL)->Label.Sid) - 1);
            DWORD il = *pIL;
            if (il >= 0x4000) integrity = ""System"";
            else if (il >= 0x3000) integrity = ""High"";
            else if (il >= 0x2000) integrity = ""Medium"";
            else integrity = ""Low"";
        }

        LUID debugLuid;
        if (LookupPrivilegeValueA(NULL, ""SeDebugPrivilege"", &debugLuid))
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

    int len = sprintf(buf,
        ""CONFIRMED=TRUE\n""
        ""CANARY_ID=%s\n""
        ""PROCESS=%s\n""
        ""PID=%lu\n""
        ""USER=%s\\%s\n""
        ""INTEGRITY=%s\n""
        ""SE_DEBUG=%s\n""
        ""TIMESTAMP=%lu\n"",
        CANARY_ID, procPath, pid, domain, username,
        integrity, hasDebug ? ""YES"" : ""NO"",
        (unsigned long)time(NULL));

    DWORD written;
    WriteFile(hFile, buf, (DWORD)len, &written, NULL);
    CloseHandle(hFile);
}");

        sb.AppendLine();

        sb.AppendLine(@"
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        WriteConfirmation();
    }
    return TRUE;
}");

        // Proxy exports for search order hijacks
        if (originalDllPath != null && File.Exists(originalDllPath))
        {
            var exports = PEAnalyzer.GetExports(originalDllPath);
            if (exports.Any())
            {
                sb.AppendLine();
                sb.AppendLine("// ─── Export forwards to original DLL ───");

                string originalForward = originalDllPath.Replace("\\", "\\\\");
                string baseName = Path.GetFileNameWithoutExtension(originalForward);

                foreach (var export in exports)
                {
                    sb.AppendLine($"#pragma comment(linker, \"/export:{export}=" +
                        $"{originalForward.Replace(".dll", "")}.{export}\")");
                }
            }
        }

        return sb.ToString();
    }

    private static bool CompileCanary(string sourcePath, string outputPath, bool is64Bit,
        string? originalDllPath)
    {
        // Try to find a C compiler
        string[] gccPaths =
        {
            @"C:\mingw64\bin\gcc.exe",
            @"C:\msys64\mingw64\bin\gcc.exe",
            @"C:\msys64\ucrt64\bin\gcc.exe",
            @"C:\TDM-GCC-64\bin\gcc.exe",
            @"C:\ProgramData\chocolatey\bin\gcc.exe",
        };

        string? compiler = gccPaths.FirstOrDefault(File.Exists);

        // Try PATH
        if (compiler == null)
        {
            compiler = FindInPath("gcc.exe");
        }

        // Try cl.exe
        if (compiler == null)
        {
            compiler = FindInPath("cl.exe");
        }

        if (compiler == null) return false;

        try
        {
            string args;
            bool isGcc = compiler.Contains("gcc", StringComparison.OrdinalIgnoreCase);

            if (isGcc)
            {
                args = $"-shared -o \"{outputPath}\" \"{sourcePath}\" " +
                       "-ladvapi32 -lkernel32 -Wl,--enable-stdcall-fixup -s";
                if (!is64Bit) args = "-m32 " + args;
            }
            else
            {
                args = $"/LD /Fe:\"{outputPath}\" \"{sourcePath}\" " +
                       "advapi32.lib kernel32.lib /link /DLL /NOLOGO";
            }

            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = compiler,
                Arguments = args,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = CanaryDir
            };

            var process = System.Diagnostics.Process.Start(psi);
            if (process == null) return false;

            process.WaitForExit(30000);

            return File.Exists(outputPath);
        }
        catch
        {
            return false;
        }
    }

    private static string BuildPowerShellCanary(string canaryId, string confirmPath)
    {
        string psPath = Path.Combine(CanaryDir, $"canary_{canaryId}.ps1");
        string escapedConfirm = confirmPath.Replace("'", "''");

        string script = $@"
try {{
    New-Item -ItemType Directory -Path '{CanaryDir.Replace("'", "''")}' -Force -ErrorAction SilentlyContinue | Out-Null
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $info = @""
CONFIRMED=TRUE
CANARY_ID={canaryId}
USER=$($identity.Name)
PROCESS=$([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
PID=$PID
TIMESTAMP=$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
""@
    Set-Content -Path '{escapedConfirm}' -Value $info -Force
}} catch {{}}
";

        File.WriteAllText(psPath, script);
        return psPath;
    }

    private static string? FindInPath(string executable)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "where",
                Arguments = executable,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            var proc = System.Diagnostics.Process.Start(psi);
            if (proc != null)
            {
                string output = proc.StandardOutput.ReadToEnd().Trim();
                proc.WaitForExit(5000);
                if (proc.ExitCode == 0 && !string.IsNullOrEmpty(output))
                    return output.Split('\n')[0].Trim();
            }
        }
        catch { }

        return null;
    }

    public static void Cleanup(string canaryId)
    {
        try
        {
            if (!Directory.Exists(CanaryDir)) return;

            string[] patterns = { $"canary_{canaryId}.*", $"{canaryId}.confirm" };
            foreach (var pattern in patterns)
            {
                foreach (var file in Directory.GetFiles(CanaryDir, pattern))
                {
                    try { File.Delete(file); } catch { }
                }
            }
        }
        catch { }
    }

    public static void CleanupAll()
    {
        try
        {
            if (Directory.Exists(CanaryDir))
            {
                foreach (var file in Directory.GetFiles(CanaryDir, "canary_*"))
                {
                    try { File.Delete(file); } catch { }
                }
                foreach (var file in Directory.GetFiles(CanaryDir, "*.confirm"))
                {
                    try { File.Delete(file); } catch { }
                }
            }
        }
        catch { }
    }
}

public class CanaryDllInfo
{
    public string CanaryId { get; set; } = "";
    public string DllPath { get; set; } = "";
    public string ConfirmPath { get; set; } = "";
    public string SourcePath { get; set; } = "";
    public bool IsProxy { get; set; }
    public string? FallbackScript { get; set; }
}
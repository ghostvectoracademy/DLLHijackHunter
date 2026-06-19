using System.Reflection;
using DLLHijackHunter.Discovery;

namespace DLLHijackHunter.Canary;

public static class CanaryDllBuilder
{
    private static readonly string CanaryDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "DLLHijackHunter");

    /// <summary>
    /// Obtain a canary DLL for the given candidate's deploy location.
    ///
    /// Default path: extract the embedded, precompiled, self-locating canary for the victim's
    /// architecture — no compiler required. The canary derives its confirmation-file path at
    /// runtime from its own loaded module path (see <see cref="GetConfirmPath"/>), so one binary
    /// per architecture serves every candidate.
    ///
    /// When the real DLL exists and exposes exports, a *functional proxy* (export-forwarding)
    /// canary is preferable because it keeps the host process alive — but that requires per-DLL
    /// compilation, so it is only attempted when an MSVC toolchain is present and falls back to
    /// the precompiled canary otherwise.
    /// </summary>
    /// <param name="deployPath">The path the canary will be copied to (the victim's hijack
    /// position). The canary's runtime confirmation path is derived from this, so it MUST be the
    /// exact path the DLL is loaded from.</param>
    public static CanaryDllInfo BuildCanary(string canaryId, string dllName,
        string? originalDllPath, bool is64Bit, string deployPath)
    {
        Directory.CreateDirectory(CanaryDir);

        string confirmPath = GetConfirmPath(deployPath);
        string canaryDllPath = Path.Combine(CanaryDir, $"canary_{canaryId}.dll");

        bool proxyDesired = originalDllPath != null && File.Exists(originalDllPath)
                            && PEAnalyzer.GetExports(originalDllPath).Any();

        // 1) Functional proxy — only when the toolchain is available.
        if (proxyDesired)
        {
            string source = GenerateCanarySource(originalDllPath);
            string sourcePath = Path.Combine(CanaryDir, $"canary_{canaryId}.c");
            File.WriteAllText(sourcePath, source);
            if (CompileCanary(sourcePath, canaryDllPath, is64Bit))
            {
                return new CanaryDllInfo
                {
                    CanaryId = canaryId,
                    DllPath = canaryDllPath,
                    ConfirmPath = confirmPath,
                    SourcePath = sourcePath,
                    IsProxy = true
                };
            }
            ScanLogger.Warn("[Canary] No MSVC toolchain for a functional proxy; using the " +
                "precompiled canary (confirms the load but does not preserve host functionality).");
        }

        // 2) Default: precompiled, self-locating canary embedded for the victim's bitness.
        if (TryExtractPrecompiled(is64Bit, canaryDllPath))
        {
            return new CanaryDllInfo
            {
                CanaryId = canaryId,
                DllPath = canaryDllPath,
                ConfirmPath = confirmPath,
                SourcePath = "",
                IsProxy = false
            };
        }

        // 3) Last resort: compile a non-proxy canary from the bundled source (only reachable if
        //    the embedded binary is missing — e.g. a stripped build).
        {
            string source = GenerateCanarySource(null);
            string sourcePath = Path.Combine(CanaryDir, $"canary_{canaryId}.c");
            File.WriteAllText(sourcePath, source);
            bool compiled = CompileCanary(sourcePath, canaryDllPath, is64Bit);
            return new CanaryDllInfo
            {
                CanaryId = canaryId,
                DllPath = compiled ? canaryDllPath : "",
                ConfirmPath = confirmPath,
                SourcePath = sourcePath,
                IsProxy = false
            };
        }
    }

    /// <summary>
    /// Confirmation-file path for a canary deployed to <paramref name="deployPath"/>. Must stay
    /// byte-for-byte in sync with the self-location logic in Resources/canary_src.c:
    /// <c>%ProgramData%\DLLHijackHunter\canary_&lt;fnv1a64(lowercased deploy path)&gt;.confirm</c>.
    /// </summary>
    public static string GetConfirmPath(string deployPath) =>
        Path.Combine(CanaryDir, $"canary_{DeployHash(deployPath)}.confirm");

    /// <summary>
    /// FNV-1a 64-bit over the ASCII deploy path with A-Z folded to a-z, formatted as 16 lowercase
    /// hex digits. Mirrors <c>fnv1a()</c> in Resources/canary_src.c exactly. ASCII paths only.
    /// </summary>
    internal static string DeployHash(string path)
    {
        ulong h = 0xcbf29ce484222325UL;
        foreach (char c in path)
        {
            int b = c & 0xFF;
            if (b >= 'A' && b <= 'Z') b += 0x20;
            h ^= (byte)b;
            h *= 0x100000001b3UL;
        }
        return h.ToString("x16");
    }

    /// <summary>
    /// Extract the embedded x64 canary once to use as the benign payload for the load-order
    /// probe (the scanner and its probe child are always x64). Returns false if unavailable.
    /// </summary>
    public static bool TryGetProbeDll(out string path)
    {
        path = Path.Combine(CanaryDir, "loadprobe.dll");
        try
        {
            Directory.CreateDirectory(CanaryDir);
            if (File.Exists(path)) return true;
            return TryExtractPrecompiled(is64Bit: true, path);
        }
        catch
        {
            return false;
        }
    }

    private static bool TryExtractPrecompiled(bool is64Bit, string outputPath)
    {
        string leaf = is64Bit ? "canary_x64.dll" : "canary_x86.dll";
        try
        {
            var asm = Assembly.GetExecutingAssembly();
            string? name = asm.GetManifestResourceNames()
                .FirstOrDefault(n => n.EndsWith(leaf, StringComparison.OrdinalIgnoreCase));
            if (name == null)
            {
                ScanLogger.Warn($"[Canary] Embedded precompiled canary '{leaf}' not found.");
                return false;
            }

            using var s = asm.GetManifestResourceStream(name);
            if (s == null) return false;
            using var fs = File.Create(outputPath);
            s.CopyTo(fs);
            return true;
        }
        catch (Exception ex)
        {
            ScanLogger.Warn($"[Canary] Could not extract precompiled canary: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Build C source for a functional proxy canary: the shared self-locating body (bundled as
    /// Resources/canary_src.c, so it cannot drift from the precompiled binary) plus name-only
    /// export forwards to the original DLL.
    /// </summary>
    private static string GenerateCanarySource(string? originalDllPath)
    {
        string body = LoadCanarySource();
        if (originalDllPath == null || !File.Exists(originalDllPath))
            return body;

        var exports = PEAnalyzer.GetExports(originalDllPath);
        if (!exports.Any())
            return body;

        var sb = new System.Text.StringBuilder(body);
        sb.AppendLine();
        sb.AppendLine("// ─── Export forwards to original DLL (EXPERIMENTAL, name-only) ───");
        // WARNING: name-only forwarding is brittle for ordinals/decorated names and may crash a
        // host that expects strict export layouts. Best-effort only.
        string forwardBaseName = Path.GetFileNameWithoutExtension(originalDllPath);
        foreach (var export in exports)
            sb.AppendLine($"#pragma comment(linker, \"/export:{export}={forwardBaseName}.{export}\")");

        return sb.ToString();
    }

    private static string? _cachedSource;

    private static string LoadCanarySource()
    {
        if (_cachedSource != null) return _cachedSource;
        try
        {
            var asm = Assembly.GetExecutingAssembly();
            string? name = asm.GetManifestResourceNames()
                .FirstOrDefault(n => n.EndsWith("canary_src.c", StringComparison.OrdinalIgnoreCase));
            if (name != null)
            {
                using var s = asm.GetManifestResourceStream(name);
                if (s != null)
                {
                    using var reader = new StreamReader(s);
                    _cachedSource = reader.ReadToEnd();
                    return _cachedSource;
                }
            }
        }
        catch { }
        _cachedSource = "";
        return _cachedSource;
    }

    private static bool CompileCanary(string sourcePath, string outputPath, bool is64Bit)
    {
        // The canary MUST match the victim process bitness or it will silently fail to load.
        // cl.exe's target architecture is selected by its toolchain environment (vcvarsall), NOT
        // by a command-line flag — so we locate vcvarsall.bat and initialise the correct target
        // ("x64" vs "x86") before invoking cl.exe through cmd. This both honours the detected
        // bitness and lets the canary build without a pre-opened developer prompt.
        string targetArch = is64Bit ? "x64" : "x86";
        string clArgs = $"/LD /Fe:\"{outputPath}\" \"{sourcePath}\" " +
                        "advapi32.lib kernel32.lib /link /DLL /NOLOGO";

        string? vcvarsall = FindVcvarsall();
        if (vcvarsall != null)
        {
            // cmd /c ""vcvarsall.bat" x64 && cl.exe ...". The outer quotes are required by cmd
            // when the whole command string is itself quoted.
            string command = $"\"\"{vcvarsall}\" {targetArch} && cl.exe {clArgs}\"";
            if (RunCompiler("cmd.exe", "/c " + command, outputPath))
                return true;

            ScanLogger.Warn($"[Canary] vcvarsall ({targetArch}) compile failed; " +
                "falling back to cl.exe on PATH.");
        }

        // Fallback: a developer command prompt may already have the toolchain on PATH.
        // Its target architecture is whatever that prompt set up and may not match is64Bit.
        string? compiler = FindInPath("cl.exe");
        if (compiler == null)
            return false;

        ScanLogger.Warn($"[Canary] Using cl.exe on PATH — its target arch may not match the " +
            $"required {targetArch} victim bitness.");
        return RunCompiler(compiler, clArgs, outputPath);
    }

    private static bool RunCompiler(string fileName, string arguments, string outputPath)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
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

    /// <summary>
    /// Locate vcvarsall.bat for the latest VS install carrying the C++ toolchain, via vswhere.
    /// </summary>
    private static string? FindVcvarsall()
    {
        try
        {
            string programFilesX86 = Environment.GetFolderPath(
                Environment.SpecialFolder.ProgramFilesX86);
            string vswhere = Path.Combine(programFilesX86,
                "Microsoft Visual Studio", "Installer", "vswhere.exe");
            if (!File.Exists(vswhere)) return null;

            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = vswhere,
                Arguments = "-latest -products * " +
                            "-requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 " +
                            "-property installationPath",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null) return null;

            string installPath = proc.StandardOutput.ReadToEnd().Trim();
            proc.WaitForExit(5000);
            if (proc.ExitCode != 0 || string.IsNullOrEmpty(installPath)) return null;

            string vcvarsall = Path.Combine(installPath.Split('\n')[0].Trim(),
                "VC", "Auxiliary", "Build", "vcvarsall.bat");
            return File.Exists(vcvarsall) ? vcvarsall : null;
        }
        catch
        {
            return null;
        }
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
                // Clean up MSVC compilation artifacts
                foreach (var ext in new[] { "*.obj", "*.lib", "*.exp", "*.pdb" })
                {
                    foreach (var file in Directory.GetFiles(CanaryDir, ext))
                    {
                        try { File.Delete(file); } catch { }
                    }
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
}

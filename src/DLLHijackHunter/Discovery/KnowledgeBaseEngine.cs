using System.Reflection;
using System.Text.Json;

namespace DLLHijackHunter.Discovery;

public static class KnowledgeBaseEngine
{
    // BinaryName -> (DllName -> reference URL). Loaded once from the embedded
    // hijacklibs.json resource so the dataset can be expanded without code changes.
    private static readonly Lazy<Dictionary<string, Dictionary<string, string>>> HijackLibsDatabase =
        new(LoadDatabase);

    // BinaryName -> list of expected parent-directory name hints (lower-case) from KB entries.
    // Used to reject matches on high-collision basenames (setup.exe, update.exe, etc.) where
    // the binary's actual path contains none of the KB-documented vendor/product directories.
    private static readonly Lazy<Dictionary<string, List<string>>> HijackLibsPathHints =
        new(LoadPathHints);

    // Basenames so generic that a name-only match is likely a false positive.
    // For these, CheckKnowledgeBase additionally verifies at least one KB path hint
    // (parent directory name) is present somewhere in the binary's actual path.
    private static readonly HashSet<string> HighCollisionNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "setup.exe", "install.exe", "installer.exe", "update.exe", "updater.exe",
        "uninstall.exe", "uninstaller.exe", "launcher.exe", "loader.exe", "helper.exe",
        "agent.exe", "service.exe", "host.exe", "bootstrap.exe", "main.exe"
    };

    /// <summary>
    /// Number of documented binaries currently loaded into the knowledge base.
    /// </summary>
    public static int EntryCount => HijackLibsDatabase.Value.Count;

    private static Dictionary<string, List<string>> LoadPathHints()
    {
        var hints = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var assembly = System.Reflection.Assembly.GetExecutingAssembly();
            using var stream = assembly.GetManifestResourceStream(
                "DLLHijackHunter.Resources.hijacklibs.json");
            if (stream == null) return hints;
            using var reader = new StreamReader(stream);
            using var doc = System.Text.Json.JsonDocument.Parse(reader.ReadToEnd());
            var root = doc.RootElement;
            var entries = root.ValueKind == System.Text.Json.JsonValueKind.Array
                ? root
                : (root.TryGetProperty("entries", out var e) ? e : default);
            if (entries.ValueKind != System.Text.Json.JsonValueKind.Array) return hints;
            foreach (var entry in entries.EnumerateArray())
            {
                if (!entry.TryGetProperty("VulnerableExecutables", out var exes) ||
                    exes.ValueKind != System.Text.Json.JsonValueKind.Array) continue;
                foreach (var exe in exes.EnumerateArray())
                {
                    if (!exe.TryGetProperty("Path", out var pathEl)) continue;
                    string? rawPath = pathEl.GetString();
                    if (string.IsNullOrEmpty(rawPath)) continue;
                    string normalized = rawPath.Replace('/', '\\');
                    string binaryName = Path.GetFileName(normalized);
                    if (string.IsNullOrEmpty(binaryName) || !binaryName.Contains('.')) continue;
                    // Collect the parent directory name as a hint (vendor/product folder).
                    string? parentDir = Path.GetFileName(Path.GetDirectoryName(normalized));
                    if (string.IsNullOrEmpty(parentDir)) continue;
                    // Expand common env-var tokens to a plain name fragment.
                    parentDir = parentDir
                        .Replace("%ProgramFiles%", "", StringComparison.OrdinalIgnoreCase)
                        .Replace("%ProgramFiles(x86)%", "", StringComparison.OrdinalIgnoreCase)
                        .Replace("%SystemRoot%", "", StringComparison.OrdinalIgnoreCase)
                        .Trim('%', '\\', '/', ' ');
                    if (parentDir.Length < 3) continue; // too short to be meaningful
                    if (!hints.TryGetValue(binaryName, out var list))
                        hints[binaryName] = list = new List<string>();
                    string hintLower = parentDir.ToLowerInvariant();
                    if (!list.Contains(hintLower)) list.Add(hintLower);
                }
            }
        }
        catch { }
        return hints;
    }

    private static Dictionary<string, Dictionary<string, string>> LoadDatabase()
    {
        // BinaryName -> (hijackable DllName -> reference URL).
        var db = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var assembly = Assembly.GetExecutingAssembly();
            using var stream = assembly.GetManifestResourceStream(
                "DLLHijackHunter.Resources.hijacklibs.json");
            if (stream == null) return db;

            using var reader = new StreamReader(stream);
            using var doc = JsonDocument.Parse(reader.ReadToEnd());
            var root = doc.RootElement;

            // The vendored dataset is the native HijackLibs export — a JSON array of
            // DLL-centric entries. A wrapper object with an "entries" array is also
            // accepted so a future generator can add provenance without breaking the loader.
            JsonElement entries = root.ValueKind == JsonValueKind.Array
                ? root
                : (root.TryGetProperty("entries", out var e) ? e : default);
            if (entries.ValueKind != JsonValueKind.Array) return db;

            foreach (var entry in entries.EnumerateArray())
            {
                // HijackLibs is DLL-centric: "Name" is the hijackable DLL, and each
                // VulnerableExecutables[].Path is an EXE susceptible to that hijack. We
                // invert this into a (binary -> dll -> reference) lookup.
                if (!entry.TryGetProperty("Name", out var nameEl)) continue;
                string? dll = nameEl.GetString();
                if (string.IsNullOrEmpty(dll)) continue;

                string reference = entry.TryGetProperty("url", out var urlEl)
                    ? urlEl.GetString() ?? "" : "";

                if (!entry.TryGetProperty("VulnerableExecutables", out var exes) ||
                    exes.ValueKind != JsonValueKind.Array)
                    continue;

                foreach (var exe in exes.EnumerateArray())
                {
                    if (!exe.TryGetProperty("Path", out var pathEl)) continue;
                    string? path = pathEl.GetString();
                    if (string.IsNullOrEmpty(path)) continue;

                    // Paths use Windows separators and embedded env vars; the basename is
                    // what we match against a discovered binary's file name.
                    string binaryName = Path.GetFileName(path.Replace('/', '\\'));
                    if (string.IsNullOrEmpty(binaryName) || !binaryName.Contains('.')) continue;

                    if (!db.TryGetValue(binaryName, out var dllMap))
                    {
                        dllMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                        db[binaryName] = dllMap;
                    }
                    dllMap[dll] = reference;
                }
            }
        }
        catch
        {
            // Fallback: an unreadable/malformed resource yields an empty KB rather than a crash.
        }
        return db;
    }

    /// <summary>
    /// Checks if a binary/dll combo is a documented vulnerability in the knowledge base.
    /// For high-collision basenames (setup.exe, update.exe, etc.) a path-hint check is
    /// also applied: at least one KB-documented parent-directory fragment must appear
    /// somewhere in the binary's actual path to avoid matching unrelated software.
    /// </summary>
    public static bool CheckKnowledgeBase(string binaryPath, string dllName, out string? referenceUrl)
    {
        referenceUrl = null;
        string binaryName = Path.GetFileName(binaryPath);

        if (!HijackLibsDatabase.Value.TryGetValue(binaryName, out var vulnerableDlls))
            return false;
        if (!vulnerableDlls.TryGetValue(dllName, out referenceUrl))
            return false;

        // High-collision names require a path-hint match to avoid false positives.
        if (HighCollisionNames.Contains(binaryName))
        {
            if (HijackLibsPathHints.Value.TryGetValue(binaryName, out var hints) && hints.Count > 0)
            {
                string pathLower = binaryPath.ToLowerInvariant();
                bool anyMatch = hints.Any(h => pathLower.Contains(h, StringComparison.Ordinal));
                if (!anyMatch)
                {
                    // Name collision — name matches KB but path does not match any known vendor
                    // directory for this binary. Suppress the KB hit to avoid false positives.
                    referenceUrl = null;
                    return false;
                }
            }
        }

        return true;
    }
}

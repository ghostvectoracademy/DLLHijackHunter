using System.Reflection;
using System.Text.Json;

namespace DLLHijackHunter.Discovery;

public static class KnowledgeBaseEngine
{
    // BinaryName -> (DllName -> reference URL). Loaded once from the embedded
    // hijacklibs.json resource so the dataset can be expanded without code changes.
    private static readonly Lazy<Dictionary<string, Dictionary<string, string>>> HijackLibsDatabase =
        new(LoadDatabase);

    /// <summary>
    /// Number of documented binaries currently loaded into the knowledge base.
    /// </summary>
    public static int EntryCount => HijackLibsDatabase.Value.Count;

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
    /// </summary>
    public static bool CheckKnowledgeBase(string binaryPath, string dllName, out string? referenceUrl)
    {
        referenceUrl = null;
        string binaryName = Path.GetFileName(binaryPath);

        if (HijackLibsDatabase.Value.TryGetValue(binaryName, out var vulnerableDlls))
        {
            if (vulnerableDlls.TryGetValue(dllName, out referenceUrl))
            {
                return true;
            }
        }
        return false;
    }
}

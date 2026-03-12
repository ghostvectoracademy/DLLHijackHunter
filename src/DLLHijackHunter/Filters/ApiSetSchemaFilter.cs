using DLLHijackHunter.Models;
using Microsoft.Win32;

namespace DLLHijackHunter.Filters;

/// <summary>
/// HARD GATE: API Set DLLs are virtual DLLs resolved by the loader.
/// They cannot be hijacked by placing files on disk.
/// </summary>
public class ApiSetSchemaFilter : IHardGate
{
    public string Name => "API Set Schema";

    private readonly HashSet<string> _apiSetNames;

    public ApiSetSchemaFilter()
    {
        _apiSetNames = BuildApiSetDatabase();
    }

    public List<HijackCandidate> Apply(List<HijackCandidate> candidates)
    {
        return candidates.Where(c =>
        {
            string dll = c.DllName.ToLowerInvariant();

            // Quick prefix check
            if (dll.StartsWith("api-ms-win-") ||
                dll.StartsWith("ext-ms-win-") ||
                dll.StartsWith("api-ms-onecoreuap-"))
            {
                c.FilterResults["ApiSetSchema"] = FilterResult.Failed;
                return false;
            }

            // Full database check
            // API set names are resolved WITHOUT version suffix
            // e.g., "api-ms-win-core-file-l1-2-1.dll" matches "api-ms-win-core-file-l1"
            string nameWithoutVersion = StripApiSetVersion(dll);
            if (_apiSetNames.Contains(nameWithoutVersion) || _apiSetNames.Contains(dll))
            {
                c.FilterResults["ApiSetSchema"] = FilterResult.Failed;
                return false;
            }

            c.FilterResults["ApiSetSchema"] = FilterResult.Passed;
            return true;
        }).ToList();
    }

    private static string StripApiSetVersion(string apiSetName)
    {
        // "api-ms-win-core-file-l1-2-1.dll" → "api-ms-win-core-file-l1"
        string name = Path.GetFileNameWithoutExtension(apiSetName);

        // Remove trailing version numbers (e.g., "-2-1", "-1-0")
        int lastDash = name.LastIndexOf('-');
        while (lastDash > 0 && int.TryParse(name[(lastDash + 1)..], out _))
        {
            name = name[..lastDash];
            lastDash = name.LastIndexOf('-');
        }

        return name;
    }

    private static HashSet<string> BuildApiSetDatabase()
    {
        var apiSets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Read from registry — most reliable source
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\ApiSetSchemaExtensions");
            // Note: API sets are primarily resolved from memory-mapped section
            // loaded by ntdll. For our purposes, prefix matching is sufficient.
        }
        catch { }

        // Known API set prefixes (comprehensive list)
        string[] knownPrefixes =
        {
            "api-ms-win-core", "api-ms-win-crt", "api-ms-win-security",
            "api-ms-win-service", "api-ms-win-shell", "api-ms-win-eventing",
            "api-ms-win-devices", "api-ms-win-appmodel", "api-ms-win-base",
            "api-ms-win-gaming", "api-ms-win-mm", "api-ms-win-net",
            "api-ms-win-ntuser", "api-ms-win-perf", "api-ms-win-power",
            "api-ms-win-ro", "api-ms-win-rtcore", "api-ms-win-shcore",
            "ext-ms-win-core", "ext-ms-win-shell", "ext-ms-win-ntuser",
            "ext-ms-win-rtcore", "ext-ms-win-networking",
            "api-ms-onecoreuap"
        };

        foreach (var prefix in knownPrefixes)
            apiSets.Add(prefix);

        // Try to enumerate actual API set DLLs from System32
        try
        {
            foreach (var file in Directory.GetFiles(Environment.SystemDirectory, "api-ms-*.dll"))
                apiSets.Add(Path.GetFileNameWithoutExtension(file).ToLowerInvariant());

            foreach (var file in Directory.GetFiles(Environment.SystemDirectory, "ext-ms-*.dll"))
                apiSets.Add(Path.GetFileNameWithoutExtension(file).ToLowerInvariant());
        }
        catch { }

        return apiSets;
    }
}
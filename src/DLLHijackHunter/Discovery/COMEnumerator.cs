using DLLHijackHunter.Models;
using Microsoft.Win32;

namespace DLLHijackHunter.Discovery;

public static class COMEnumerator
{
    public static List<DiscoveryContext> EnumerateCOMObjects()
    {
        var results = new List<DiscoveryContext>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            using var clsidKey = Registry.ClassesRoot.OpenSubKey("CLSID");
            if (clsidKey == null) return results;

            foreach (var clsid in clsidKey.GetSubKeyNames())
            {
                try
                {
                    // Check InprocServer32 (DLL-based COM objects)
                    EnumerateComServer(clsidKey, clsid, "InprocServer32", seen, results);

                    // Check LocalServer32 (EXE-based COM objects)
                    EnumerateComServer(clsidKey, clsid, "LocalServer32", seen, results);
                }
                catch { continue; }
            }
        }
        catch { }

        return results;
    }

    private static void EnumerateComServer(RegistryKey clsidKey, string clsid,
        string serverType, HashSet<string> seen, List<DiscoveryContext> results)
    {
        using var serverKey = clsidKey.OpenSubKey($"{clsid}\\{serverType}");
        if (serverKey == null) return;

        var serverPath = serverKey.GetValue(null) as string;
        if (string.IsNullOrEmpty(serverPath)) return;

        string expanded = Environment.ExpandEnvironmentVariables(serverPath).Trim('"');

        // Strip command-line arguments for LocalServer32
        if (serverType == "LocalServer32" && expanded.Contains(' ') && !File.Exists(expanded))
        {
            expanded = CommandLineParser.ExtractExecutablePath(expanded);
        }

        if (seen.Contains(expanded)) return;
        seen.Add(expanded);

        // Get display name
        using var nameKey = clsidKey.OpenSubKey(clsid);
        var displayName = nameKey?.GetValue(null) as string ?? clsid;

        if (File.Exists(expanded))
        {
            results.Add(new DiscoveryContext
            {
                BinaryPath = expanded,
                TriggerType = TriggerType.COM,
                TriggerIdentifier = clsid,
                DisplayName = $"{displayName} [{serverType}]",
                RunAsAccount = "VARIES",
                IsAutoStart = false
            });
        }
        else
        {
            // COM server doesn't exist — phantom COM hijack!
            results.Add(new DiscoveryContext
            {
                BinaryPath = expanded,
                TriggerType = TriggerType.COM,
                TriggerIdentifier = clsid,
                DisplayName = $"[PHANTOM COM] {displayName} [{serverType}]",
                RunAsAccount = "VARIES",
                IsAutoStart = false
            });
        }
    }
}
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
                    using var inprocKey = clsidKey.OpenSubKey($"{clsid}\\InprocServer32");
                    if (inprocKey == null) continue;

                    var dllPath = inprocKey.GetValue(null) as string;
                    if (string.IsNullOrEmpty(dllPath)) continue;

                    dllPath = Environment.ExpandEnvironmentVariables(dllPath);

                    if (seen.Contains(dllPath)) continue;
                    seen.Add(dllPath);

                    // Get display name
                    using var nameKey = clsidKey.OpenSubKey(clsid);
                    var displayName = nameKey?.GetValue(null) as string ?? clsid;

                    if (File.Exists(dllPath))
                    {
                        results.Add(new DiscoveryContext
                        {
                            BinaryPath = dllPath,
                            TriggerType = TriggerType.COM,
                            TriggerIdentifier = clsid,
                            DisplayName = displayName,
                            RunAsAccount = "VARIES",
                            IsAutoStart = false
                        });
                    }
                    else
                    {
                        // COM DLL doesn't exist — phantom COM hijack!
                        results.Add(new DiscoveryContext
                        {
                            BinaryPath = dllPath,
                            TriggerType = TriggerType.COM,
                            TriggerIdentifier = clsid,
                            DisplayName = $"[PHANTOM COM] {displayName}",
                            RunAsAccount = "VARIES",
                            IsAutoStart = false
                        });
                    }
                }
                catch { continue; }
            }
        }
        catch { }

        return results;
    }
}
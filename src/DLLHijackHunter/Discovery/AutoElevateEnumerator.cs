using DLLHijackHunter.Models;
using Microsoft.Win32;
using System.Collections.Concurrent;
using System.Text;

namespace DLLHijackHunter.Discovery;

public static class AutoElevateEnumerator
{
    public static List<DiscoveryContext> EnumerateAutoElevateBinaries()
    {
        var results = new ConcurrentBag<DiscoveryContext>();

        // 1. Scan EXEs for AutoElevate Manifests
        string system32 = Environment.SystemDirectory;
        string syswow64 = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);

        ScanDirectory(system32, results);

        if (Directory.Exists(syswow64) &&
            !string.Equals(system32, syswow64, StringComparison.OrdinalIgnoreCase))
        {
            ScanDirectory(syswow64, results);
        }

        // 2. Scan COM Objects for Elevation\Enabled=1
        ScanComElevation(results);

        return results.ToList();
    }

    private static void ScanDirectory(string directory, ConcurrentBag<DiscoveryContext> results)
    {
        try
        {
            var files = Directory.EnumerateFiles(directory, "*.exe", SearchOption.TopDirectoryOnly);

            Parallel.ForEach(files, file =>
            {
                if (IsAutoElevate(file))
                {
                    results.Add(new DiscoveryContext
                    {
                        BinaryPath = file,
                        TriggerType = TriggerType.UACBypass,
                        TriggerIdentifier = "Manifest AutoElevate",
                        DisplayName = Path.GetFileName(file),
                        RunAsAccount = "NT AUTHORITY\\SYSTEM (via UAC Bypass)",
                        StartType = "MANUAL",
                        IsAutoStart = false
                    });
                }
            });
        }
        catch { }
    }

    /// <summary>
    /// Scans HKLM\SOFTWARE\Classes\CLSID for COM objects with Elevation\Enabled=1.
    /// These are hidden UAC bypass vectors (Fodhelper, CMSTPLUA, etc.).
    /// COM elevation grants High Integrity to the current user — NOT SYSTEM.
    /// </summary>
    private static void ScanComElevation(ConcurrentBag<DiscoveryContext> results)
    {
        try
        {
            using var clsidKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Classes\CLSID");
            if (clsidKey == null) return;

            foreach (var clsid in clsidKey.GetSubKeyNames())
            {
                try
                {
                    using var elevationKey = clsidKey.OpenSubKey($@"{clsid}\Elevation");
                    if (elevationKey == null) continue;

                    var enabled = elevationKey.GetValue("Enabled");
                    if (enabled == null || (int)enabled != 1) continue;

                    // Check InprocServer32 (DLL-based COM objects)
                    TryAddComServer(clsidKey, clsid, "InprocServer32", results);

                    // Check LocalServer32 (EXE-based COM objects, e.g. Fodhelper)
                    TryAddComServer(clsidKey, clsid, "LocalServer32", results);
                }
                catch { continue; }
            }
        }
        catch { }
    }

    private static void TryAddComServer(RegistryKey clsidKey, string clsid,
        string serverType, ConcurrentBag<DiscoveryContext> results)
    {
        try
        {
            using var serverKey = clsidKey.OpenSubKey($@"{clsid}\{serverType}");
            var serverPath = serverKey?.GetValue(null) as string;

            if (string.IsNullOrEmpty(serverPath)) return;

            string expanded = Environment.ExpandEnvironmentVariables(serverPath).Trim('"');

            // Strip command-line arguments (LocalServer32 can have them)
            if (expanded.Contains(' ') && !File.Exists(expanded))
            {
                expanded = expanded.Split(' ')[0].Trim('"');
            }

            if (!File.Exists(expanded)) return;

            results.Add(new DiscoveryContext
            {
                BinaryPath = expanded,
                TriggerType = TriggerType.UACBypass,
                TriggerIdentifier = $"COM AutoElevate ({clsid})",
                DisplayName = $"{Path.GetFileName(expanded)} [{serverType}]",
                RunAsAccount = "HIGH_INTEGRITY\\CurrentUser",
                StartType = "COM_INSTANTIATION",
                IsAutoStart = false
            });
        }
        catch { }
    }

    private static bool IsAutoElevate(string filePath)
    {
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

            int readSize = (int)Math.Min(fs.Length, 2 * 1024 * 1024);
            byte[] buffer = new byte[readSize];
            fs.Read(buffer, 0, readSize);

            string content = Encoding.UTF8.GetString(buffer);

            int idx = content.IndexOf("autoElevate", StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return false;

            // Extract a larger context window to validate XML structure
            int start = Math.Max(0, idx - 20);
            int end = Math.Min(content.Length, idx + 100);
            string snippet = content[start..end];

            // Validate it's actually an XML manifest element, not coincidental binary data
            return snippet.Contains("<autoElevate>true</autoElevate>", StringComparison.OrdinalIgnoreCase);
        }
        catch { }

        return false;
    }
}
// src/DLLHijackHunter/Discovery/StartupItemEnumerator.cs

using DLLHijackHunter.Models;
using Microsoft.Win32;

namespace DLLHijackHunter.Discovery;

public static class StartupItemEnumerator
{
    private static readonly string[] RunKeyPaths =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    };

    public static List<DiscoveryContext> EnumerateStartupItems()
    {
        var results = new List<DiscoveryContext>();

        // HKLM Run keys (run as SYSTEM context during startup)
        foreach (var keyPath in RunKeyPaths)
        {
            EnumerateRunKey(Registry.LocalMachine, keyPath, "Interactive User", results);
        }

        // HKCU Run keys (run as current user)
        foreach (var keyPath in RunKeyPaths)
        {
            EnumerateRunKey(Registry.CurrentUser, keyPath,
                Native.TokenHelper.GetCurrentUsername(), results);
        }

        // Startup folders
        EnumerateStartupFolder(
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Native.TokenHelper.GetCurrentUsername(), results);

        EnumerateStartupFolder(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
            "NT AUTHORITY\\SYSTEM", results);

        // AppInit_DLLs
        EnumerateAppInitDlls(results);

        // IFEO
        EnumerateIFEO(results);

        return results;
    }

    private static void EnumerateRunKey(RegistryKey root, string keyPath,
        string runAs, List<DiscoveryContext> results)
    {
        try
        {
            using var key = root.OpenSubKey(keyPath);
            if (key == null) return;

            foreach (var valueName in key.GetValueNames())
            {
                var value = key.GetValue(valueName) as string;
                if (string.IsNullOrEmpty(value)) continue;

                string binaryPath = ParseCommandPath(value);
                if (!File.Exists(binaryPath)) continue;

                results.Add(new DiscoveryContext
                {
                    BinaryPath = binaryPath,
                    TriggerType = TriggerType.RunKey,
                    TriggerIdentifier = $"{root.Name}\\{keyPath}\\{valueName}",
                    DisplayName = valueName,
                    RunAsAccount = runAs,
                    IsAutoStart = true
                });
            }
        }
        catch { }
    }

    private static void EnumerateStartupFolder(string folderPath, string runAs,
        List<DiscoveryContext> results)
    {
        if (!Directory.Exists(folderPath)) return;

        try
        {
            foreach (var file in Directory.GetFiles(folderPath))
            {
                string ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext is ".exe" or ".bat" or ".cmd" or ".vbs" or ".js" or ".lnk")
                {
                    string binaryPath = file;
                    if (ext == ".lnk")
                    {
                        try
                        {
                            Type? t = Type.GetTypeFromProgID("WScript.Shell");
                            if (t != null)
                            {
                                object shell = Activator.CreateInstance(t)!;
                                object shortcut = t.InvokeMember("CreateShortcut", System.Reflection.BindingFlags.InvokeMethod, null, shell, new object[] { file })!;
                                string target = (string)shortcut.GetType().InvokeMember("TargetPath", System.Reflection.BindingFlags.GetProperty, null, shortcut, null)!;
                                if (!string.IsNullOrEmpty(target))
                                {
                                    binaryPath = target;
                                }
                            }
                        }
                        catch { /* Fallback to file path if resolution fails */ }
                    }

                    results.Add(new DiscoveryContext
                    {
                        BinaryPath = binaryPath,
                        TriggerType = TriggerType.Startup,
                        TriggerIdentifier = file,
                        DisplayName = Path.GetFileNameWithoutExtension(file),
                        RunAsAccount = runAs,
                        IsAutoStart = true
                    });
                }
            }
        }
        catch { }
    }

    private static void EnumerateAppInitDlls(List<DiscoveryContext> results)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows");
            if (key == null) return;

            var loadAppInit = key.GetValue("LoadAppInit_DLLs");
            if (loadAppInit == null || (int)loadAppInit == 0) return;

            var appInitDlls = key.GetValue("AppInit_DLLs") as string;
            if (!string.IsNullOrEmpty(appInitDlls))
            {
                // AppInit_DLLs are loaded into every user-mode process
                results.Add(new DiscoveryContext
                {
                    BinaryPath = appInitDlls,
                    TriggerType = TriggerType.Startup,
                    TriggerIdentifier = "AppInit_DLLs",
                    DisplayName = "AppInit_DLLs: " + appInitDlls,
                    RunAsAccount = "ALL_PROCESSES",
                    IsAutoStart = true
                });
            }
        }
        catch { }
    }

    private static void EnumerateIFEO(List<DiscoveryContext> results)
    {
        try
        {
            using var ifeoKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
            if (ifeoKey == null) return;

            foreach (var subkeyName in ifeoKey.GetSubKeyNames())
            {
                using var subkey = ifeoKey.OpenSubKey(subkeyName);
                if (subkey == null) continue;

                var debugger = subkey.GetValue("Debugger") as string;
                var globalFlag = subkey.GetValue("GlobalFlag");

                if (!string.IsNullOrEmpty(debugger))
                {
                    results.Add(new DiscoveryContext
                    {
                        BinaryPath = ParseCommandPath(debugger),
                        TriggerType = TriggerType.Startup,
                        TriggerIdentifier = $"IFEO\\{subkeyName}",
                        DisplayName = $"IFEO Debugger for {subkeyName}",
                        RunAsAccount = "VARIES",
                        IsAutoStart = true
                    });
                }
            }
        }
        catch { }
    }

    private static string ParseCommandPath(string command)
    {
        command = command.Trim();
        if (command.StartsWith('"'))
        {
            int end = command.IndexOf('"', 1);
            if (end > 0) return command[1..end];
        }

        string expanded = Environment.ExpandEnvironmentVariables(command);
        // Note: Simple split on space breaks on unquoted paths with spaces
        string path = CommandLineParser.ExtractExecutablePath(expanded);
        return path.Trim('"');
    }
}
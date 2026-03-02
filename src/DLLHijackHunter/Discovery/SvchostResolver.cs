// src/DLLHijackHunter/Discovery/SvchostResolver.cs

using Microsoft.Win32;

namespace DLLHijackHunter.Discovery;

public static class SvchostResolver
{
    /// <summary>
    /// For svchost-hosted services, the real DLL is stored in the registry.
    /// HKLM\SYSTEM\CurrentControlSet\Services\{name}\Parameters\ServiceDll
    /// </summary>
    public static string? GetServiceDll(string serviceName)
    {
        try
        {
            using var paramKey = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{serviceName}\Parameters");

            var serviceDll = paramKey?.GetValue("ServiceDll") as string;
            if (!string.IsNullOrEmpty(serviceDll))
                return Environment.ExpandEnvironmentVariables(serviceDll);

            using var svcKey = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{serviceName}");

            serviceDll = svcKey?.GetValue("ServiceDll") as string;
            if (!string.IsNullOrEmpty(serviceDll))
                return Environment.ExpandEnvironmentVariables(serviceDll);
        }
        catch { }

        return null;
    }

    /// <summary>
    /// Get all DLLs loaded by a svchost group.
    /// </summary>
    public static List<(string serviceName, string dllPath)> GetSvchostGroupDlls(string groupName)
    {
        var results = new List<(string, string)>();

        try
        {
            using var svchostKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost");
            if (svchostKey == null) return results;

            var services = svchostKey.GetValue(groupName) as string[];
            if (services == null) return results;

            foreach (var svc in services)
            {
                string? dll = GetServiceDll(svc.Trim());
                if (dll != null)
                    results.Add((svc.Trim(), dll));
            }
        }
        catch { }

        return results;
    }
}
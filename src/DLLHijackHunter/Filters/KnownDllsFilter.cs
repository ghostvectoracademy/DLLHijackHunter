// src/DLLHijackHunter/Filters/KnownDllsFilter.cs

using DLLHijackHunter.Models;
using Microsoft.Win32;

namespace DLLHijackHunter.Filters;

/// <summary>
/// HARD GATE: KnownDLLs are loaded from a shared section object cache.
/// The filesystem search order is NOT used for these DLLs.
/// EXCEPTION: .local files can bypass KnownDLLs (handled separately).
/// </summary>
public class KnownDllsFilter : IHardGate
{
    public string Name => "KnownDLLs Cache";

    private readonly HashSet<string> _knownDlls;
    private readonly HashSet<string> _knownDlls32; // WoW64 KnownDLLs

    public KnownDllsFilter()
    {
        _knownDlls = LoadKnownDlls(@"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs");
        _knownDlls32 = LoadKnownDlls(@"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs32");
    }

    public List<HijackCandidate> Apply(List<HijackCandidate> candidates)
    {
        return candidates.Where(c =>
        {
            string dll = c.DllName.ToLowerInvariant();

            // If this is a .local bypass, don't kill it — .local overrides KnownDLLs
            if (c.Type == HijackType.DotLocal)
            {
                c.FilterResults["KnownDLLs"] = FilterResult.Passed;
                c.Notes.Add("KnownDLL bypassed via .local redirection");
                return true;
            }

            // Check both native and WoW64 KnownDLLs
            bool isKnownDll = _knownDlls.Contains(dll) || _knownDlls32.Contains(dll);

            if (isKnownDll)
            {
                c.FilterResults["KnownDLLs"] = FilterResult.Failed;
                return false;
            }

            c.FilterResults["KnownDLLs"] = FilterResult.Passed;
            return true;
        }).ToList();
    }

    private static HashSet<string> LoadKnownDlls(string registryPath)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(registryPath);
            if (key == null) return result;

            foreach (var valueName in key.GetValueNames())
            {
                var value = key.GetValue(valueName) as string;
                if (!string.IsNullOrEmpty(value))
                {
                    result.Add(value.ToLowerInvariant());
                }
            }
        }
        catch { }

        return result;
    }
}
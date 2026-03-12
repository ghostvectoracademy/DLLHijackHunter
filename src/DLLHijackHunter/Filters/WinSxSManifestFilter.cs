// src/DLLHijackHunter/Filters/WinSxSManifestFilter.cs

using DLLHijackHunter.Models;
using DLLHijackHunter.Discovery;

namespace DLLHijackHunter.Filters;

/// <summary>
/// SOFT GATE: If the binary has a manifest with SxS bindings for THIS specific DLL,
/// the loader uses WinSxS instead of search order.
/// Penalty: High if manifest specifically covers this DLL, low if manifest exists but is generic.
/// </summary>
public class WinSxSManifestFilter : ISoftGate
{
    public string Name => "WinSxS / Manifest";

    // Common DLLs that are typically handled by SxS/manifests
    private static readonly HashSet<string> SxSManagedDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "comctl32.dll", "gdiplus.dll", "msvcr100.dll", "msvcr110.dll",
        "msvcr120.dll", "msvcr140.dll", "msvcp100.dll", "msvcp110.dll",
        "msvcp120.dll", "msvcp140.dll", "vcruntime140.dll",
        "ucrtbase.dll", "mfc140u.dll", "mfc140.dll",
        "atl100.dll", "atl110.dll", "atl120.dll", "atl140.dll"
    };

    public (double penalty, string? reason) Evaluate(HijackCandidate candidate)
    {
        try
        {
            var pe = PEAnalyzer.Analyze(candidate.BinaryPath);

            if (!pe.HasEmbeddedManifest)
            {
                candidate.ManifestCoversThisSpecificDll = false;
                candidate.FilterResults["WinSxS"] = FilterResult.Passed;
                return (0, null);
            }

            // Binary has a manifest — check if this specific DLL is SxS-managed
            bool isSxsDll = SxSManagedDlls.Contains(candidate.DllName);

            if (!string.IsNullOrEmpty(pe.ManifestContent))
            {
                bool explicitlyBound = pe.ManifestContent.Contains($"\"{candidate.DllName}\"", StringComparison.OrdinalIgnoreCase) ||
                                       pe.ManifestContent.Contains($"name=\"{candidate.DllName}\"", StringComparison.OrdinalIgnoreCase);

                bool assemblyBound = false;
                if (isSxsDll)
                {
                    if (candidate.DllName.StartsWith("msv", StringComparison.OrdinalIgnoreCase) || candidate.DllName.StartsWith("ucrt", StringComparison.OrdinalIgnoreCase))
                        assemblyBound = pe.ManifestContent.Contains("Microsoft.VC", StringComparison.OrdinalIgnoreCase);
                    else if (candidate.DllName.StartsWith("comctl32", StringComparison.OrdinalIgnoreCase))
                        assemblyBound = pe.ManifestContent.Contains("Microsoft.Windows.Common-Controls", StringComparison.OrdinalIgnoreCase);
                    else if (candidate.DllName.StartsWith("gdiplus", StringComparison.OrdinalIgnoreCase))
                        assemblyBound = pe.ManifestContent.Contains("Microsoft.Windows.GdiPlus", StringComparison.OrdinalIgnoreCase);
                    else
                        assemblyBound = true;
                }

                if (explicitlyBound || assemblyBound)
                {
                    candidate.ManifestCoversThisSpecificDll = true;
                    candidate.FilterResults["WinSxS"] = FilterResult.Failed;
                    return (40, $"Manifest (heuristically extracted/best-effort) explicitly binds {candidate.DllName} or its SxS assembly.");
                }
            }
            else if (isSxsDll)
            {
                candidate.ManifestCoversThisSpecificDll = true;
                candidate.FilterResults["WinSxS"] = FilterResult.Failed;
                return (30, $"{candidate.DllName} is typically SxS-managed and binary has an unparsed manifest (heuristically detected, best-effort).");
            }

            // Manifest exists but doesn't specifically cover this DLL
            // Small penalty — manifest might affect search order via other mechanisms
            candidate.ManifestCoversThisSpecificDll = false;
            candidate.FilterResults["WinSxS"] = FilterResult.Passed;
            return (5, "Binary has manifest (heuristically detected, best-effort) but it doesn't cover this specific DLL");
        }
        catch
        {
            candidate.FilterResults["WinSxS"] = FilterResult.Skipped;
            return (0, null);
        }
    }
}
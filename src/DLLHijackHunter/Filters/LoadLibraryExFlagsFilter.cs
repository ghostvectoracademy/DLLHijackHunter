// src/DLLHijackHunter/Filters/LoadLibraryExFlagsFilter.cs

using DLLHijackHunter.Models;
using DLLHijackHunter.Discovery;

namespace DLLHijackHunter.Filters;

/// <summary>
/// SOFT GATE: If the binary uses LoadLibraryEx with LOAD_LIBRARY_SEARCH_SYSTEM32,
/// the DLL search order is bypassed. Disassembly would give certainty but is expensive.
/// We use heuristics from the import table instead.
/// </summary>
public class LoadLibraryExFlagsFilter : ISoftGate
{
    public string Name => "LoadLibraryEx Flags";

    // Cache PE analysis results to avoid re-parsing
    private readonly Dictionary<string, PEAnalysisResult> _cache = new(StringComparer.OrdinalIgnoreCase);

    public (double penalty, string? reason) Evaluate(HijackCandidate candidate)
    {
        try
        {
            if (!_cache.TryGetValue(candidate.BinaryPath, out var pe))
            {
                pe = PEAnalyzer.Analyze(candidate.BinaryPath);
                _cache[candidate.BinaryPath] = pe;
            }

            if (pe.AnalysisError != null)
            {
                candidate.LoadLibAnalysisConfidence = AnalysisConfidence.Unknown;
                candidate.FilterResults["LoadLibFlags"] = FilterResult.Skipped;
                return (0, null);
            }

            // Check 1: Does the binary call SetDefaultDllDirectories?
            // This globally restricts the search order for the entire process.
            if (pe.CallsSetDefaultDllDirectories)
            {
                candidate.LoadLibAnalysisConfidence = AnalysisConfidence.IndirectCall;
                candidate.FilterResults["LoadLibFlags"] = FilterResult.Failed;
                return (20, "Binary calls SetDefaultDllDirectories() — may restrict " +
                           "DLL search order globally for the process. " +
                           "Cannot determine exact flags without disassembly.");
            }

            // Check 2: Does the binary call AddDllDirectory?
            // This adds specific directories but doesn't necessarily block others.
            if (pe.CallsAddDllDirectory)
            {
                candidate.LoadLibAnalysisConfidence = AnalysisConfidence.IndirectCall;
                candidate.FilterResults["LoadLibFlags"] = FilterResult.Failed;
                return (10, "Binary calls AddDllDirectory() — may modify search path. " +
                           "Standard search order might still apply for some DLLs.");
            }

            // Check 3: Does the binary call SetDllDirectory?
            // SetDllDirectory("") removes CWD from search order.
            // SetDllDirectory("path") adds a specific directory.
            if (pe.CallsSetDllDirectory)
            {
                // Only relevant for CWD hijacks
                if (candidate.Type == HijackType.CWD)
                {
                    candidate.LoadLibAnalysisConfidence = AnalysisConfidence.IndirectCall;
                    candidate.FilterResults["LoadLibFlags"] = FilterResult.Failed;
                    return (25, "Binary calls SetDllDirectory() — likely removes CWD " +
                               "from search order, blocking CWD-based hijacking.");
                }

                // For non-CWD hijacks, SetDllDirectory is less relevant
                candidate.FilterResults["LoadLibFlags"] = FilterResult.Passed;
                return (5, "Binary calls SetDllDirectory() — minimal impact on " +
                          "non-CWD based hijacking.");
            }

            // Check 4: Does the binary use LoadLibraryEx at all?
            if (pe.UsesLoadLibraryEx)
            {
                // It MIGHT use LOAD_LIBRARY_SEARCH_SYSTEM32 but we can't tell
                // without disassembly. Apply small penalty since we're uncertain.
                candidate.LoadLibAnalysisConfidence = AnalysisConfidence.IndirectCall;
                candidate.FilterResults["LoadLibFlags"] = FilterResult.Failed;
                return (10, "Binary imports LoadLibraryEx — flags unknown without " +
                           "disassembly. May use LOAD_LIBRARY_SEARCH_SYSTEM32 " +
                           "for some DLL loads.");
            }

            // Check 5: Binary only uses LoadLibrary (no Ex variant)
            // Standard search order always applies.
            if (pe.UsesLoadLibrary && !pe.UsesLoadLibraryEx)
            {
                candidate.LoadLibAnalysisConfidence = AnalysisConfidence.Certain;
                candidate.FilterResults["LoadLibFlags"] = FilterResult.Passed;
                return (0, null); // Standard LoadLibrary — no secure flags possible
            }

            // Check 6: Binary doesn't call any LoadLibrary variant
            // DLLs are loaded via import table — standard search order applies.
            candidate.LoadLibAnalysisConfidence = AnalysisConfidence.Certain;
            candidate.FilterResults["LoadLibFlags"] = FilterResult.Passed;
            return (0, null);
        }
        catch
        {
            candidate.FilterResults["LoadLibFlags"] = FilterResult.Skipped;
            return (0, null);
        }
    }
}
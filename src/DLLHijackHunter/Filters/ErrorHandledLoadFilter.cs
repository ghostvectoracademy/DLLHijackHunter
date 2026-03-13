using DLLHijackHunter.Models;

namespace DLLHijackHunter.Filters;

/// <summary>
/// SOFT GATE: If LoadLibrary is error-handled, the DLL is "optional."
/// BUT: DllMain ALWAYS runs before the error check.
/// Minimal penalty — code execution still achieved.
/// </summary>
public class ErrorHandledLoadFilter : ISoftGate
{
    public string Name => "Error-Handled Optional Load";

    public (double penalty, string? reason) Evaluate(HijackCandidate candidate)
    {
        // For standard imports (not LoadLibrary calls), error handling doesn't apply.
        // The loader will fail the entire process if the DLL is missing.
        if (candidate.Type == HijackType.Phantom)
        {
            // Phantom DLLs in the import table = process won't even start
            // unless they're delay-loaded
            candidate.FilterResults["ErrorHandled"] = FilterResult.Passed;
            return (0, null);
        }

        // Only penalize if the binary uses dynamic loading (LoadLibrary),
        // where error handling could swallow the load. Standard IAT imports
        // are not error-handled and fail fatally.
        if (candidate.LoadLibAnalysisConfidence != Models.AnalysisConfidence.Unknown &&
            candidate.LoadLibAnalysisConfidence != Models.AnalysisConfidence.Certain)
        {
            candidate.FilterResults["ErrorHandled"] = FilterResult.Passed;
            return (5, "Binary uses dynamic loading — DllMain still executes before " +
                       "any error handling. Code execution achieved regardless.");
        }

        candidate.FilterResults["ErrorHandled"] = FilterResult.Passed;
        return (0, null);
    }
}
// src/DLLHijackHunter/Filters/ErrorHandledLoadFilter.cs

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

        // For delay-loaded DLLs, the load is deferred and may be error-handled
        // Small penalty since DllMain still runs
        candidate.FilterResults["ErrorHandled"] = FilterResult.Passed;
        return (5, "DllMain executes before any error handling. " +
                   "Code execution achieved regardless.");
    }
}
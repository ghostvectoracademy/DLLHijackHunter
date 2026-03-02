// src/DLLHijackHunter/Filters/IFilter.cs

using DLLHijackHunter.Models;

namespace DLLHijackHunter.Filters;

public interface IHardGate
{
    string Name { get; }
    List<HijackCandidate> Apply(List<HijackCandidate> candidates);
}

public interface ISoftGate
{
    string Name { get; }

    /// <summary>
    /// Evaluate the candidate and return a confidence penalty (0 = no concern, 50 = major concern).
    /// Does NOT remove the candidate — only adjusts confidence.
    /// </summary>
    (double penalty, string? reason) Evaluate(HijackCandidate candidate);
}
// src/DLLHijackHunter/Filters/PrivilegeDeltaFilter.cs

using DLLHijackHunter.Models;
using DLLHijackHunter.Native;

namespace DLLHijackHunter.Filters;

/// <summary>
/// SOFT GATE: Does this hijack give the attacker MORE privilege?
/// Same-privilege hijacks are still useful for persistence/evasion.
/// Penalty: 15% for same-privilege (not useless, just different use case).
/// </summary>
public class PrivilegeDeltaFilter : ISoftGate
{
    public string Name => "Privilege Escalation Delta";

    private readonly int _currentPrivLevel;

    public PrivilegeDeltaFilter()
    {
        _currentPrivLevel = TokenHelper.GetCurrentPrivilegeLevel();
    }

    public (double penalty, string? reason) Evaluate(HijackCandidate candidate)
    {
        int targetPrivLevel = GetTargetPrivilegeLevel(candidate.RunAsAccount);

        if (targetPrivLevel > _currentPrivLevel)
        {
            // Privilege escalation — no penalty
            candidate.UseCases.Add("Privilege Escalation");
            candidate.FilterResults["PrivDelta"] = FilterResult.Passed;
            return (0, null);
        }

        if (targetPrivLevel == _currentPrivLevel)
        {
            // Same privilege — still useful for persistence and evasion
            candidate.UseCases.Add("Persistence");
            candidate.UseCases.Add("Defense Evasion");

            // If target is a signed binary, it's great for EDR bypass
            try
            {
                var pe = Discovery.PEAnalyzer.Analyze(candidate.BinaryPath);
                if (pe.IsSigned)
                {
                    candidate.UseCases.Add("EDR Bypass (signed binary injection)");
                    candidate.UseCases.Add("Application Whitelisting Bypass");
                }
            }
            catch { }

            candidate.FilterResults["PrivDelta"] = FilterResult.Failed;
            return (15, $"Same privilege level (target={candidate.RunAsAccount}, " +
                       $"current={TokenHelper.GetCurrentUsername()}). " +
                       "Still useful for persistence/evasion.");
        }

        // Target runs at LOWER privilege — minimal value
        candidate.FilterResults["PrivDelta"] = FilterResult.Failed;
        return (30, $"Target runs at lower privilege than current user");
    }

    private static int GetTargetPrivilegeLevel(string runAsAccount)
    {
        string upper = runAsAccount.ToUpperInvariant();

        if (upper.Contains("SYSTEM") || upper.Contains("LOCALSYSTEM"))
            return 4;
        if (upper.Contains("LOCAL SERVICE") || upper.Contains("NETWORK SERVICE") ||
            upper.Contains("LOCALSERVICE") || upper.Contains("NETWORKSERVICE"))
            return 3;
        if (upper.Contains("ADMINISTRATOR") || upper.Contains("ADMIN"))
            return 3;

        return 2; // standard user
    }
}
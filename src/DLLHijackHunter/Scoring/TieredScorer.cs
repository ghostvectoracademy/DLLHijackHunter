// src/DLLHijackHunter/Scoring/TieredScorer.cs

using DLLHijackHunter.Models;

namespace DLLHijackHunter.Scoring;

public class TieredScorer
{
    public void ScoreAll(List<HijackCandidate> candidates)
    {
        foreach (var c in candidates)
        {
            Score(c);
        }
    }

    public void Score(HijackCandidate c)
    {
        // ═══ Canary result adjustments ═══
        if (c.CanaryResult == CanaryResult.Fired)
        {
            c.Confidence = 100.0;
        }
        else if (c.CanaryResult == CanaryResult.Failed)
        {
            c.Confidence -= 20;
        }
        else if (c.CanaryResult == CanaryResult.Timeout)
        {
            c.Confidence -= 10;
        }
        // NotTested = no change (but UAC bypass gets a bonus for inherent reliability)
        if (c.CanaryResult == CanaryResult.NotTested && c.Trigger == TriggerType.UACBypass)
        {
            c.Confidence += 10;
        }

        c.Confidence = Math.Clamp(c.Confidence, 0, 100);

        // ═══ Determine tier ═══
        c.Tier = c.CanaryResult == CanaryResult.Fired ? ConfidenceTier.Confirmed :
                 c.Confidence >= 80 ? ConfidenceTier.High :
                 c.Confidence >= 50 ? ConfidenceTier.Medium :
                 c.Confidence >= 20 ? ConfidenceTier.Low :
                 ConfidenceTier.Informational;

        // ═══ Impact score (separate from confidence) ═══
        c.ImpactScore = CalculateImpact(c);

        // ═══ Final score = weighted combination ═══
        c.FinalScore = (c.Confidence / 100.0 * 0.4 + c.ImpactScore / 10.0 * 0.6) * 10.0;
        c.FinalScore = Math.Round(Math.Clamp(c.FinalScore, 0, 10), 1);

        // ═══ Add use cases if not already present ═══
        if (c.Trigger == TriggerType.UACBypass && !c.UseCases.Contains("Silent UAC Bypass"))
            c.UseCases.Add("Silent UAC Bypass (Admin execution without prompt)");

        if (c.IsSimulatedCopyAttack && !c.UseCases.Contains("Copy & Side-Load"))
            c.UseCases.Add("Copy & Side-Load (Copy EXE to writable folder, drop DLL next to it)");
            
        if (c.SurvivesReboot && !c.UseCases.Contains("Persistence"))
            c.UseCases.Add("Persistence");

        if (c.Type == HijackType.Phantom && !c.UseCases.Contains("Clean Hijack (no file replaced)"))
            c.UseCases.Add("Clean Hijack (no file replaced)");
    }

    private static double CalculateImpact(HijackCandidate c)
    {
        double impact = 0;

        // Privilege gained (0-4)
        string runAs = c.ConfirmedPrivilege ?? c.RunAsAccount;
        string upper = runAs.ToUpperInvariant();

        if (upper.Contains("SYSTEM"))
            impact += 4.0;
        else if (upper.Contains("ADMINISTRATOR") || upper.Contains("ADMIN") ||
                 upper.Contains("LOCAL SERVICE") || upper.Contains("NETWORK SERVICE"))
            impact += 3.0;
        else
            impact += 1.0;

        // Trigger reliability (0-3)
        impact += c.Trigger switch
        {
            TriggerType.Service when c.ServiceStartType == "AUTO_START" => 3.0,
            TriggerType.ScheduledTask when c.TaskFrequency < TimeSpan.FromHours(1) => 2.5,
            TriggerType.UACBypass => 2.8,
            TriggerType.Startup or TriggerType.RunKey => 2.0,
            TriggerType.Service => 1.5,
            TriggerType.COM => 1.0,
            _ => 0.5
        };

        // Stealth (0-2)
        impact += c.Type switch
        {
            HijackType.Phantom => 2.0,
            HijackType.DotLocal => 1.8,
            HijackType.SearchOrder => 1.5,
            HijackType.SideLoad => 1.5,
            HijackType.EnvPath => 1.0,
            HijackType.CWD => 0.5,
            _ => 1.0
        };

        // Persistence bonus
        if (c.SurvivesReboot) impact += 1.0;

        return Math.Clamp(impact, 0, 10);
    }
}
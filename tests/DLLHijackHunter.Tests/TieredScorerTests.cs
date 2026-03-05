// tests/DLLHijackHunter.Tests/TieredScorerTests.cs

using DLLHijackHunter.Models;
using DLLHijackHunter.Scoring;
using Xunit;

namespace DLLHijackHunter.Tests;

public class TieredScorerTests
{
    private readonly TieredScorer _scorer = new();

    private static HijackCandidate CreateCandidate(
        CanaryResult canaryResult = CanaryResult.NotTested,
        double confidence = 85,
        string runAs = "NT AUTHORITY\\SYSTEM",
        TriggerType trigger = TriggerType.Service,
        string? startType = "AUTO_START",
        HijackType type = HijackType.SearchOrder,
        bool survivesReboot = true)
    {
        return new HijackCandidate
        {
            BinaryPath = @"C:\Test\test.exe",
            DllName = "test.dll",
            CanaryResult = canaryResult,
            Confidence = confidence,
            RunAsAccount = runAs,
            Trigger = trigger,
            ServiceStartType = startType,
            Type = type,
            SurvivesReboot = survivesReboot
        };
    }

    [Fact]
    public void Score_CanaryFired_SetsConfirmedTier()
    {
        var candidate = CreateCandidate(canaryResult: CanaryResult.Fired);

        _scorer.Score(candidate);

        Assert.Equal(ConfidenceTier.Confirmed, candidate.Tier);
        Assert.Equal(100.0, candidate.Confidence);
    }

    [Fact]
    public void Score_CanaryFailed_ReducesConfidence()
    {
        var candidate = CreateCandidate(canaryResult: CanaryResult.Failed, confidence: 85);

        _scorer.Score(candidate);

        Assert.Equal(65.0, candidate.Confidence);
    }

    [Fact]
    public void Score_CanaryTimeout_ReducesConfidenceBy10()
    {
        var candidate = CreateCandidate(canaryResult: CanaryResult.Timeout, confidence: 85);

        _scorer.Score(candidate);

        Assert.Equal(75.0, candidate.Confidence);
    }

    [Fact]
    public void Score_HighConfidence_SetsHighTier()
    {
        var candidate = CreateCandidate(confidence: 90);

        _scorer.Score(candidate);

        Assert.Equal(ConfidenceTier.High, candidate.Tier);
    }

    [Fact]
    public void Score_MediumConfidence_SetsMediumTier()
    {
        var candidate = CreateCandidate(confidence: 60);

        _scorer.Score(candidate);

        Assert.Equal(ConfidenceTier.Medium, candidate.Tier);
    }

    [Fact]
    public void Score_LowConfidence_SetsLowTier()
    {
        var candidate = CreateCandidate(confidence: 30);

        _scorer.Score(candidate);

        Assert.Equal(ConfidenceTier.Low, candidate.Tier);
    }

    [Fact]
    public void Score_SystemAutoStart_HasHighImpact()
    {
        var candidate = CreateCandidate(
            runAs: "NT AUTHORITY\\SYSTEM",
            trigger: TriggerType.Service,
            startType: "AUTO_START",
            type: HijackType.Phantom,
            survivesReboot: true);

        _scorer.Score(candidate);

        // SYSTEM (4) + AutoStart Service (3) + Phantom (2) + Reboot (1) = 10
        Assert.Equal(10.0, candidate.ImpactScore);
    }

    [Fact]
    public void Score_UserManualTrigger_HasLowImpact()
    {
        var candidate = CreateCandidate(
            runAs: "DESKTOP\\User",
            trigger: TriggerType.Unknown,
            startType: null,
            type: HijackType.CWD,
            survivesReboot: false);

        _scorer.Score(candidate);

        // User (1) + Unknown trigger (0.5) + CWD (0.5) + no reboot (0) = 2.0
        Assert.Equal(2.0, candidate.ImpactScore);
    }

    [Fact]
    public void Score_FinalScore_IsClamped0To10()
    {
        var candidate = CreateCandidate(confidence: 100);

        _scorer.Score(candidate);

        Assert.InRange(candidate.FinalScore, 0.0, 10.0);
    }

    [Fact]
    public void Score_SurvivesReboot_AddsPersistenceUseCase()
    {
        var candidate = CreateCandidate(survivesReboot: true);

        _scorer.Score(candidate);

        Assert.Contains("Persistence", candidate.UseCases);
    }

    [Fact]
    public void Score_PhantomType_AddsCleanHijackUseCase()
    {
        var candidate = CreateCandidate(type: HijackType.Phantom);

        _scorer.Score(candidate);

        Assert.Contains("Clean Hijack (no file replaced)", candidate.UseCases);
    }

    [Fact]
    public void Score_NotPhantomAndNoReboot_NoExtraUseCases()
    {
        var candidate = CreateCandidate(
            type: HijackType.SearchOrder,
            survivesReboot: false);

        _scorer.Score(candidate);

        Assert.DoesNotContain("Persistence", candidate.UseCases);
        Assert.DoesNotContain("Clean Hijack (no file replaced)", candidate.UseCases);
    }

    [Fact]
    public void ScoreAll_ProcessesMultipleCandidates()
    {
        var candidates = new List<HijackCandidate>
        {
            CreateCandidate(confidence: 90),
            CreateCandidate(confidence: 50),
            CreateCandidate(confidence: 25)
        };

        _scorer.ScoreAll(candidates);

        Assert.All(candidates, c => Assert.True(c.FinalScore > 0));
        Assert.Equal(ConfidenceTier.High, candidates[0].Tier);
        Assert.Equal(ConfidenceTier.Medium, candidates[1].Tier);
        Assert.Equal(ConfidenceTier.Low, candidates[2].Tier);
    }

    [Fact]
    public void Score_ConfidenceClampedToZero_WhenHeavilyPenalized()
    {
        var candidate = CreateCandidate(
            canaryResult: CanaryResult.Failed,
            confidence: 10); // 10 - 20 = -10, clamped to 0

        _scorer.Score(candidate);

        Assert.Equal(0.0, candidate.Confidence);
        Assert.Equal(ConfidenceTier.Informational, candidate.Tier);
    }

    [Fact]
    public void Score_FinalScoreFormula_IsCorrect()
    {
        var candidate = CreateCandidate(
            confidence: 80,
            runAs: "NT AUTHORITY\\SYSTEM",
            trigger: TriggerType.Service,
            startType: "AUTO_START",
            type: HijackType.SearchOrder,
            survivesReboot: true);

        _scorer.Score(candidate);

        // Confidence = 80
        // Impact = SYSTEM(4) + AutoStart(3) + SearchOrder(1.5) + Reboot(1) = 9.5
        // Final = (80/100 * 0.4 + 9.5/10 * 0.6) * 10 = (0.32 + 0.57) * 10 = 8.9
        double expectedFinal = Math.Round(
            (80.0 / 100.0 * 0.4 + 9.5 / 10.0 * 0.6) * 10.0, 1);
        Assert.Equal(expectedFinal, candidate.FinalScore);
    }

    [Fact]
    public void Score_UACBypass_AddsSilentUACBypassUseCase()
    {
        var candidate = CreateCandidate(trigger: TriggerType.UACBypass);

        _scorer.Score(candidate);

        Assert.Contains(candidate.UseCases, u => u.Contains("Silent UAC Bypass"));
    }

    [Fact]
    public void Score_UACBypass_HasCorrectImpactScore()
    {
        var candidate = CreateCandidate(
            runAs: "NT AUTHORITY\\SYSTEM",
            trigger: TriggerType.UACBypass,
            type: HijackType.Phantom,
            survivesReboot: false);

        _scorer.Score(candidate);

        // SYSTEM (4) + UACBypass trigger (2.8) + Phantom (2.0) + no reboot (0) = 8.8
        Assert.Equal(8.8, candidate.ImpactScore);
    }

    [Fact]
    public void Score_UACBypass_GetsConfidenceBonus()
    {
        var candidate = CreateCandidate(
            canaryResult: CanaryResult.NotTested,
            confidence: 85,
            trigger: TriggerType.UACBypass);

        _scorer.Score(candidate);

        // 85 + 10 (UAC bypass bonus) = 95
        Assert.Equal(95.0, candidate.Confidence);
    }

    [Fact]
    public void Score_UACBypassSideLoad_AddsCopyAndSideLoadUseCase()
    {
        var candidate = CreateCandidate(trigger: TriggerType.UACBypass, type: HijackType.SideLoad);
        candidate.IsSimulatedCopyAttack = true;

        _scorer.Score(candidate);

        Assert.Contains(candidate.UseCases, u => u.Contains("Copy & Side-Load"));
        Assert.Contains(candidate.UseCases, u => u.Contains("Silent UAC Bypass"));
    }

    [Fact]
    public void Score_UACBypassSideLoad_HasCorrectImpactScore()
    {
        var candidate = CreateCandidate(
            runAs: "NT AUTHORITY\\SYSTEM",
            trigger: TriggerType.UACBypass,
            type: HijackType.SideLoad,
            survivesReboot: false);

        _scorer.Score(candidate);

        // SYSTEM (4) + UACBypass trigger (2.8) + SideLoad (1.5) + no reboot (0) = 8.3
        Assert.Equal(8.3, candidate.ImpactScore);
    }
}

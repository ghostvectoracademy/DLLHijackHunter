// src/DLLHijackHunter/Models/HijackCandidate.cs

namespace DLLHijackHunter.Models;

public enum HijackType
{
    Phantom,        // DLL doesn't exist anywhere on disk
    SearchOrder,    // DLL exists but attacker can place one earlier in search order
    SideLoad,       // DLL loaded by legitimate app from its own directory
    CWD,            // DLL loaded from Current Working Directory
    DotLocal,       // .local file redirection
    KnownDllBypass, // Bypassing KnownDLLs via .local or WoW64
    EnvPath,        // Writable directory in PATH environment variable
    AppInitDll,     // AppInit_DLLs registry abuse
    IFEO,           // Image File Execution Options
    AppCertDll      // AppCertDLLs registry abuse
}

public enum TriggerType
{
    Service,
    ScheduledTask,
    Startup,
    COM,
    WMI,
    RunKey,
    Manual,
    UACBypass,
    Unknown
}

public enum FilterResult
{
    Passed,
    Failed,
    Skipped,
    NotTested
}

public enum CanaryResult
{
    NotTested,
    Fired,
    Failed,
    Timeout,
    Blocked
}

public enum ConfidenceTier
{
    Confirmed,   // Canary-proven, 100% exploitable
    High,        // 80–100% confidence
    Medium,      // 50–79% confidence
    Low,         // 20–49% confidence
    Informational // <20% but still worth knowing
}

public enum AnalysisConfidence
{
    Certain,         // Direct constant in instruction
    CertainDirect,   // Direct call with known flag
    IndirectCall,    // Call through register/pointer
    Unknown          // Could not determine
}

public class HijackCandidate
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];

    // ─── Identity ───
    public string BinaryPath { get; set; } = "";
    public string BinarySHA256 { get; set; } = "";
    public string DllName { get; set; } = "";
    public string? DllLegitPath { get; set; }

    // ─── Classification ───
    public HijackType Type { get; set; }
    public string HijackWritablePath { get; set; } = "";

    // ─── Trigger context ───
    public TriggerType Trigger { get; set; } = TriggerType.Unknown;
    public string TriggerIdentifier { get; set; } = "";
    public bool IsSimulatedCopyAttack { get; set; } // Attacker copies EXE to writable folder
    public string RunAsAccount { get; set; } = "";
    public string? ServiceStartType { get; set; }
    public TimeSpan? TaskFrequency { get; set; }

    // ─── Filter results ───
    public Dictionary<string, FilterResult> FilterResults { get; set; } = new();

    // ─── Soft gate analysis details ───
    public bool ManifestCoversThisSpecificDll { get; set; }
    public AnalysisConfidence LoadLibAnalysisConfidence { get; set; } = AnalysisConfidence.Unknown;
    public bool IsProtectedProcess { get; set; }
    public bool HasWinVerifyTrust { get; set; }

    // ─── Canary confirmation ───
    public CanaryResult CanaryResult { get; set; } = CanaryResult.NotTested;
    public string? ConfirmedPrivilege { get; set; }
    public string? ConfirmedIntegrityLevel { get; set; }
    public bool? ConfirmedSeDebug { get; set; }
    public bool AppStillFunctional { get; set; } = true;

    // ─── Scoring ───
    public ConfidenceTier Tier { get; set; } = ConfidenceTier.Informational;
    public double Confidence { get; set; }
    public double ImpactScore { get; set; }
    public double FinalScore { get; set; }
    public bool SurvivesReboot { get; set; }

    // ─── Metadata ───
    public List<string> UseCases { get; set; } = new();
    public List<string> Notes { get; set; } = new();
    public List<string> ProxyExports { get; set; } = new();
    public string DiscoverySource { get; set; } = "static"; // "static" or "etw"
    public DateTime DiscoveredAt { get; set; } = DateTime.UtcNow;

    public override string ToString() =>
        $"[{Tier}] {BinaryPath} → {DllName} ({Type}) via {Trigger} as {RunAsAccount} " +
        $"[Confidence={Confidence:F0}% Impact={ImpactScore:F1}]";
}
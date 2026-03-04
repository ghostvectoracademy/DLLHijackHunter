// src/DLLHijackHunter/Models/DiscoveryContext.cs

namespace DLLHijackHunter.Models;

/// <summary>
/// Unified execution context representing a binary discovered via static enumeration
/// or ETW runtime tracing. Combines fields from both discovery sources.
/// </summary>
public class DiscoveryContext
{
    // ─── Static Discovery Fields ───
    public string BinaryPath { get; set; } = "";
    public TriggerType TriggerType { get; set; }
    public string TriggerIdentifier { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string RunAsAccount { get; set; } = "";
    public string StartType { get; set; } = "";
    public bool IsAutoStart { get; set; }
    public bool IsSvchostService { get; set; }
    public TimeSpan? RepeatInterval { get; set; }

    // ─── ETW Runtime Fields ───
    public int Pid { get; set; }
    public string CommandLine { get; set; } = "";
    public string CWD { get; set; } = "";
    public string TokenUser { get; set; } = "";
    public string IntegrityLevel { get; set; } = "";
    public bool IsProtected { get; set; }
    public List<string> FailedDllLookups { get; set; } = new();
    public List<string> LoadedDlls { get; set; } = new();
}

// src/DLLHijackHunter/Models/ScanResult.cs

namespace DLLHijackHunter.Models;

public class ScanResult
{
    public string Hostname { get; set; } = Environment.MachineName;
    public string OSVersion { get; set; } = Environment.OSVersion.ToString();
    public DateTime ScanDate { get; set; } = DateTime.UtcNow;
    public string ScanMode { get; set; } = "";
    public string ProfileUsed { get; set; } = "";
    public TimeSpan ScanDuration { get; set; }

    // Counts
    public int TotalCandidatesDiscovered { get; set; }
    public int EliminatedByHardGates { get; set; }
    public int SurvivedSoftGates { get; set; }

    // Results by tier
    public List<HijackCandidate> Confirmed { get; set; } = new();
    public List<HijackCandidate> High { get; set; } = new();
    public List<HijackCandidate> Medium { get; set; } = new();
    public List<HijackCandidate> Low { get; set; } = new();

    public List<HijackCandidate> AllFindings =>
        Confirmed.Concat(High).Concat(Medium).Concat(Low)
                 .OrderByDescending(c => c.FinalScore).ToList();

    public int TotalFindings =>
        Confirmed.Count + High.Count + Medium.Count + Low.Count;
}
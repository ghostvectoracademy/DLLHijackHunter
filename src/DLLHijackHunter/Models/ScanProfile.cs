// src/DLLHijackHunter/Models/ScanProfile.cs

namespace DLLHijackHunter.Models;

public class ScanProfile
{
    public string Name { get; set; } = "default";
    public double MinConfidence { get; set; } = 20;
    public bool RunCanary { get; set; } = true;
    public bool RunETW { get; set; } = true;
    public bool IncludeSamePrivilege { get; set; } = true;
    public bool IncludePPL { get; set; } = true;
    public int CanaryTimeoutSeconds { get; set; } = 15;
    public int ETWDurationSeconds { get; set; } = 120;
    public bool TriggerServices { get; set; } = true;
    public bool TriggerScheduledTasks { get; set; } = true;
    public bool TriggerCOM { get; set; } = false;
    public bool ConfirmedOnly { get; set; } = false;
    public List<string> UseCaseFilter { get; set; } = new();
    public string OutputFormat { get; set; } = "json";
    public string? OutputPath { get; set; }
    public bool Verbose { get; set; } = false;
    public string? TargetPath { get; set; }
    public bool TriggerAutoElevate { get; set; } = false;

    public static ScanProfile Aggressive => new()
    {
        Name = "aggressive",
        MinConfidence = 15,
        RunCanary = true,
        RunETW = true,
        IncludeSamePrivilege = true,
        IncludePPL = true,
        CanaryTimeoutSeconds = 30,
        TriggerServices = true,
        TriggerScheduledTasks = true,
        TriggerCOM = true,
        TriggerAutoElevate = true
    };

    public static ScanProfile Strict => new()
    {
        Name = "strict",
        MinConfidence = 80,
        RunCanary = true,
        RunETW = true,
        IncludeSamePrivilege = false,
        IncludePPL = false,
        CanaryTimeoutSeconds = 15,
        TriggerServices = true,
        TriggerScheduledTasks = true,
        TriggerCOM = false
    };

    public static ScanProfile Safe => new()
    {
        Name = "safe",
        MinConfidence = 50,
        RunCanary = false,
        RunETW = false,
        IncludeSamePrivilege = true,
        IncludePPL = false,
        CanaryTimeoutSeconds = 0,
        TriggerServices = false,
        TriggerScheduledTasks = false,
        TriggerCOM = false
    };

    public static ScanProfile RedTeam => new()
    {
        Name = "redteam",
        MinConfidence = 50,
        RunCanary = true,
        RunETW = true,
        IncludeSamePrivilege = false,
        IncludePPL = false,
        CanaryTimeoutSeconds = 20,
        ConfirmedOnly = true,
        TriggerServices = true,
        TriggerScheduledTasks = true,
        TriggerCOM = true
    };

    public static ScanProfile UACBypass => new()
    {
        Name = "uac-bypass",
        MinConfidence = 20,
        RunCanary = false, // Canarying AutoElevate apps causes UAC prompts if they fail, keep it safe
        RunETW = false,
        IncludeSamePrivilege = false,
        IncludePPL = false,
        TriggerServices = false,
        TriggerScheduledTasks = false,
        TriggerCOM = false,
        TriggerAutoElevate = true
    };

    public static ScanProfile FromName(string name) => name.ToLower() switch
    {
        "aggressive" => Aggressive,
        "strict" => Strict,
        "safe" => Safe,
        "redteam" => RedTeam,
        "uac-bypass" => UACBypass,
        _ => new ScanProfile { Name = name }
    };
}
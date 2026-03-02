// src/DLLHijackHunter/Models/ProcessContext.cs

namespace DLLHijackHunter.Models;

public class ProcessContext
{
    public int Pid { get; set; }
    public string ImagePath { get; set; } = "";
    public string CommandLine { get; set; } = "";
    public string CWD { get; set; } = "";
    public string TokenUser { get; set; } = "";
    public string IntegrityLevel { get; set; } = "";
    public bool IsProtected { get; set; }
    public List<string> FailedDllLookups { get; set; } = new();
    public List<string> LoadedDlls { get; set; } = new();
}
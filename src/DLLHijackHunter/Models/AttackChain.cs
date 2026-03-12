namespace DLLHijackHunter.Models;

public class AttackChain
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public string TargetPrivilege { get; set; } = "";
    public List<AttackStep> Steps { get; set; } = new();
}

public class AttackStep
{
    public int StepNumber { get; set; }
    public string Action { get; set; } = "";
    public string Details { get; set; } = "";
    public HijackCandidate? Finding { get; set; }
}
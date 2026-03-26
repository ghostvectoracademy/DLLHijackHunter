using DLLHijackHunter.Models;
using System.Security.Principal;

namespace DLLHijackHunter.Scoring;

public class AttackChainCorrelator
{
    public List<AttackChain> BuildChains(List<HijackCandidate> findings)
    {
        var chains = new List<AttackChain>();
        string currentUser;
        try { currentUser = WindowsIdentity.GetCurrent().Name; }
        catch { currentUser = "Unknown"; }

        // 1. Categorize findings
        var uacBypasses = findings.Where(c => c.Trigger == TriggerType.UACBypass).ToList();
        
        var systemServices = findings.Where(c => 
            (c.RunAsAccount.Equals("NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase) || 
             c.RunAsAccount.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase) ||
             c.ConfirmedPrivilege?.Equals("NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase) == true) &&
            c.Trigger != TriggerType.UACBypass).ToList();

        // 2. Build "The Direct Path" (User -> SYSTEM)
        // We do this first because if a Direct Path exists, it's the most critical
        var directSystem = systemServices.Where(c => c.Type == HijackType.EnvPath || c.Type == HijackType.CWD).ToList();
        if (directSystem.Any())
        {
            var bestDirect = directSystem.OrderByDescending(c => c.FinalScore).First();
            chains.Add(new AttackChain
            {
                Name = "The Direct Path (User → SYSTEM)",
                Description = "A misconfiguration allows a standard user to hijack a SYSTEM process directly.",
                TargetPrivilege = "NT AUTHORITY\\SYSTEM",
                Steps = new List<AttackStep>
                {
                    new() { StepNumber = 1, Action = $"Start as Standard User ({currentUser})", Details = "" },
                    new() { StepNumber = 2, Action = $"Plant malicious {bestDirect.DllName}", Details = $"Write payload to: {bestDirect.HijackWritablePath}", Finding = bestDirect },
                    new() { StepNumber = 3, Action = $"Trigger: {bestDirect.TriggerIdentifier}", Details = bestDirect.SurvivesReboot ? "Wait for reboot." : "Execute trigger." },
                    new() { StepNumber = 4, Action = "💥 SYSTEM Shell Achieved!", Details = "Bypassed Admin entirely." }
                }
            });
        }

        // 3. Build "The Ladder" (User -> Admin -> SYSTEM)
        // Only use SYSTEM services that are NOT already in the direct path (i.e. require Admin to write to)
        var ladderSystemServices = systemServices.Except(directSystem).ToList();
        
        if (uacBypasses.Any() && ladderSystemServices.Any())
        {
            var bestUac = uacBypasses.OrderByDescending(c => c.FinalScore).First();
            var bestSystem = ladderSystemServices.OrderByDescending(c => c.FinalScore).First();

            var chain = new AttackChain
            {
                Name = "The Ladder (User → Admin → SYSTEM)",
                Description = "Chains a silent UAC bypass to gain write access, followed by a SYSTEM service hijack.",
                TargetPrivilege = "NT AUTHORITY\\SYSTEM",
                Steps = new List<AttackStep>
                {
                    new() { 
                        StepNumber = 1, 
                        Action = $"Start as Standard User ({currentUser})", 
                        Details = "Initial foothold." 
                    },
                    new() { 
                        StepNumber = 2, 
                        Action = $"Execute Silent UAC Bypass via {bestUac.DllName}", 
                        Details = $"Copy {Path.GetFileName(bestUac.BinaryPath)} to writable folder, drop DLL, and execute.",
                        Finding = bestUac
                    },
                    new() { 
                        StepNumber = 3, 
                        Action = "Achieve High Integrity (Local Admin)", 
                        Details = "You now have permissions to write to protected locations." 
                    },
                    new() { 
                        StepNumber = 4, 
                        Action = $"Plant malicious {bestSystem.DllName}", 
                        Details = $"Write payload to: {bestSystem.HijackWritablePath}",
                        Finding = bestSystem
                    },
                    new() { 
                        StepNumber = 5, 
                        Action = $"Trigger: {bestSystem.TriggerIdentifier}", 
                        Details = bestSystem.SurvivesReboot ? "Wait for reboot or restart service." : "Execute trigger."
                    },
                    new() { 
                        StepNumber = 6, 
                        Action = "💥 SYSTEM Shell Achieved!", 
                        Details = "Full machine compromise." 
                    }
                }
            };
            chains.Add(chain);
        }

        // 4. Build "Persistence" Chain (Initial Compromise -> AutoStart)
        var persistanceFindings = findings.Where(c => c.SurvivesReboot && c.Trigger != TriggerType.Service).ToList();
        
        if (persistanceFindings.Any())
        {
            var bestPersistance = persistanceFindings.OrderByDescending(c => c.FinalScore).First();
            chains.Add(new AttackChain
            {
                Name = "The Long Con (User → Persistence)",
                Description = "Establishes a stealthy persistence mechanism that survives reboots.",
                TargetPrivilege = bestPersistance.RunAsAccount ?? currentUser,
                Steps = new List<AttackStep>
                {
                    new() { StepNumber = 1, Action = "Achieve Initial Compromise", Details = "Assume attacker has gained initial access." },
                    new() { StepNumber = 2, Action = $"Plant malicious {bestPersistance.DllName}", Details = $"Write payload to: {bestPersistance.HijackWritablePath}", Finding = bestPersistance },
                    new() { StepNumber = 3, Action = "Wait for Reboot / User Logon", Details = "The DLL will be automatically loaded." },
                    new() { StepNumber = 4, Action = "💥 Persistent Shell Achieved!", Details = $"Running as {bestPersistance.RunAsAccount ?? "the logged-in user"} every time the system starts." }
                }
            });
        }

        return chains;
    }
}
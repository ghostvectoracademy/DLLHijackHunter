using DLLHijackHunter.Models;
using DLLHijackHunter.Discovery;
using System.Diagnostics;

namespace DLLHijackHunter.Filters;

/// <summary>
/// SOFT GATE: Protected Process Light (PPL) enforces DLL signature at kernel level.
/// Non-PPL signature checks run AFTER DllMain — our code already executed.
/// </summary>
public class SignatureVerificationFilter : ISoftGate
{
    public string Name => "Signature Verification / PPL";

    // Binaries known to run as PPL
    private static readonly HashSet<string> KnownPPLBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "csrss.exe", "smss.exe", "lsass.exe", "services.exe",
        "wininit.exe", "MsMpEng.exe", "SenseIR.exe",
        "SecurityHealthService.exe", "svchost.exe" // svchost CAN be PPL for specific services
    };

    public (double penalty, string? reason) Evaluate(HijackCandidate candidate)
    {
        string binaryName = Path.GetFileName(candidate.BinaryPath).ToLowerInvariant();

        // Check for PPL binary
        if (KnownPPLBinaries.Contains(binaryName))
        {
            // svchost is PPL for SOME services, not all
            if (binaryName == "svchost.exe")
            {
                // Check if this specific service is PPL
                bool isPPLService = IsServicePPL(candidate.TriggerIdentifier);
                if (isPPLService)
                {
                    candidate.IsProtectedProcess = true;
                    candidate.FilterResults["Signature"] = FilterResult.Failed;
                    return (45, $"Service {candidate.TriggerIdentifier} runs under PPL svchost. " +
                               "Kernel enforces DLL signature. Requires PPL bypass.");
                }

                candidate.FilterResults["Signature"] = FilterResult.Passed;
                return (0, null);
            }

            candidate.IsProtectedProcess = true;
            candidate.FilterResults["Signature"] = FilterResult.Failed;
            return (45, $"{binaryName} is in the tool's hardcoded Protected Process Light (PPL) list. " +
                       "Kernel enforces DLL signature verification if truly PPL.");
        }

        // For non-PPL: even if binary calls WinVerifyTrust, DllMain runs FIRST
        // But check for FORCE_INTEGRITY DllCharacteristic
        try
        {
            var pe = PEAnalyzer.Analyze(candidate.BinaryPath);
            if (pe.ForceIntegrity)
            {
                candidate.IsProtectedProcess = true;
                candidate.FilterResults["Signature"] = FilterResult.Failed;
                return (40, $"{binaryName} has FORCE_INTEGRITY DllCharacteristic set. " +
                           "Kernel enforces code integrity for all loaded modules.");
            }
        }
        catch { }

        candidate.FilterResults["Signature"] = FilterResult.Passed;
        return (0, null);
    }

    private static bool IsServicePPL(string serviceName)
    {
        // Services known to run under PPL svchost
        var pplServices = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "WinDefend", "SecurityHealthService", "Sense",
            "SgrmBroker", "KeyIso", "SamSs"
        };

        return pplServices.Contains(serviceName);
    }
}
// src/DLLHijackHunter/Filters/WritabilityFilter.cs

using DLLHijackHunter.Models;
using DLLHijackHunter.Native;

namespace DLLHijackHunter.Filters;

/// <summary>
/// HARD GATE: If we can't write to the hijack path, we can't exploit it.
/// Uses proper ACL checking (not file-write test which lies under UAC virtualization).
/// </summary>
public class WritabilityFilter : IHardGate
{
    public string Name => "Directory Writability (ACL)";

    public List<HijackCandidate> Apply(List<HijackCandidate> candidates)
    {
        return candidates.Where(c =>
        {
            // Skip PATH-type entries that were already verified
            if (c.Type == HijackType.EnvPath)
            {
                c.FilterResults["Writability"] = FilterResult.Passed;
                return true;
            }

            // Skip simulated copy attacks (attacker controls the target folder)
            if (c.IsSimulatedCopyAttack)
            {
                c.FilterResults["Writability"] = FilterResult.Passed;
                return true;
            }

            string targetPath = c.HijackWritablePath;
            if (string.IsNullOrEmpty(targetPath))
            {
                c.FilterResults["Writability"] = FilterResult.Failed;
                return false;
            }

            bool writable;

            if (c.Type == HijackType.DotLocal)
            {
                // For .local, we need to create the .local directory
                string? dotLocalParent = Path.GetDirectoryName(
                    Path.GetDirectoryName(targetPath));
                writable = dotLocalParent != null &&
                          AclChecker.IsDirectoryWritableByCurrentUser(dotLocalParent);
            }
            else
            {
                writable = AclChecker.CanWriteFile(targetPath);
            }

            c.FilterResults["Writability"] = writable ? FilterResult.Passed : FilterResult.Failed;
            return writable;
        }).ToList();
    }
}
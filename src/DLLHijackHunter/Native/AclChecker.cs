using System.Security.AccessControl;
using System.Security.Principal;

namespace DLLHijackHunter.Native;

public static class AclChecker
{
    /// <summary>
    /// Proper ACL-based writability check. Does NOT fall for UAC virtualization.
    /// </summary>
    public static bool IsDirectoryWritableByCurrentUser(string path)
    {
        if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
            return false;

        try
        {
            var identity = WindowsIdentity.GetCurrent();
            var dirInfo = new DirectoryInfo(path);
            var acl = dirInfo.GetAccessControl(AccessControlSections.Access);
            var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier));

            bool writeAllowed = false;
            bool writeDenied = false;

            foreach (FileSystemAccessRule rule in rules)
            {
                if (!RuleAppliesToIdentity(rule.IdentityReference, identity))
                    continue;

                bool hasWrite = (rule.FileSystemRights & FileSystemRights.Write) != 0 ||
                               (rule.FileSystemRights & FileSystemRights.CreateFiles) != 0 ||
                               (rule.FileSystemRights & FileSystemRights.FullControl) != 0 ||
                               (rule.FileSystemRights & FileSystemRights.Modify) != 0;

                if (!hasWrite) continue;

                if (rule.AccessControlType == AccessControlType.Deny)
                    writeDenied = true;
                else if (rule.AccessControlType == AccessControlType.Allow)
                    writeAllowed = true;
            }

            return writeAllowed && !writeDenied;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Check if we can create a directory at the given path.
    /// </summary>
    public static bool CanCreateDirectory(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;

        string? parent = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(parent)) return false;

        return IsDirectoryWritableByCurrentUser(parent);
    }

    /// <summary>
    /// Check if a specific file path is writable.
    /// </summary>
    public static bool CanWriteFile(string filePath)
    {
        string? dir = Path.GetDirectoryName(filePath);
        if (string.IsNullOrEmpty(dir)) return false;

        if (!Directory.Exists(dir))
            return CanCreateDirectory(dir);

        return IsDirectoryWritableByCurrentUser(dir);
    }

    private static bool RuleAppliesToIdentity(IdentityReference ruleIdentity, WindowsIdentity currentUser)
    {
        try
        {
            SecurityIdentifier? ruleSid = ruleIdentity as SecurityIdentifier;
            if (ruleSid == null)
            {
                try { ruleSid = (SecurityIdentifier)ruleIdentity.Translate(typeof(SecurityIdentifier)); }
                catch { return false; }
            }

            if (currentUser.User != null && ruleSid.Equals(currentUser.User))
                return true;

            if (currentUser.Groups != null)
            {
                foreach (var group in currentUser.Groups)
                {
                    if (ruleSid.Equals(group))
                        return true;
                }
            }

            string sidValue = ruleSid.Value;
            return sidValue is "S-1-1-0" or "S-1-5-11" or "S-1-5-32-545";
        }
        catch
        {
            return false;
        }
    }
}
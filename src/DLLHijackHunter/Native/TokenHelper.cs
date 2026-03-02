// src/DLLHijackHunter/Native/TokenHelper.cs

using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace DLLHijackHunter.Native;

public static class TokenHelper
{
    public static string GetCurrentUsername()
    {
        try { return WindowsIdentity.GetCurrent().Name; }
        catch { return "Unknown"; }
    }

    public static string GetCurrentIntegrityLevel()
    {
        try
        {
            return GetProcessIntegrityLevel(NativeMethods.GetCurrentProcess());
        }
        catch { return "Unknown"; }
    }

    public static int GetCurrentPrivilegeLevel()
    {
        string il = GetCurrentIntegrityLevel();
        return il switch
        {
            "System" => 4,
            "High" => 3,
            "Medium" => 2,
            "Low" => 1,
            _ => 0
        };
    }

    public static string GetProcessIntegrityLevel(IntPtr processHandle)
    {
        IntPtr tokenHandle = IntPtr.Zero;
        IntPtr buffer = IntPtr.Zero;

        try
        {
            if (!NativeMethods.OpenProcessToken(processHandle,
                NativeMethods.TOKEN_QUERY, out tokenHandle))
                return "Unknown";

            NativeMethods.GetTokenInformation(tokenHandle,
                NativeMethods.TokenIntegrityLevel, IntPtr.Zero, 0, out int length);

            if (length == 0) return "Unknown";

            buffer = Marshal.AllocHGlobal(length);

            if (!NativeMethods.GetTokenInformation(tokenHandle,
                NativeMethods.TokenIntegrityLevel, buffer, length, out _))
                return "Unknown";

            IntPtr sidPtr = Marshal.ReadIntPtr(buffer);

            IntPtr pCount = NativeMethods.GetSidSubAuthorityCount(sidPtr);
            if (pCount == IntPtr.Zero) return "Unknown";

            byte count = Marshal.ReadByte(pCount);
            if (count == 0) return "Unknown";

            IntPtr pAuth = NativeMethods.GetSidSubAuthority(sidPtr, (uint)(count - 1));
            if (pAuth == IntPtr.Zero) return "Unknown";

            uint il = (uint)Marshal.ReadInt32(pAuth);

            return il switch
            {
                >= NativeMethods.SECURITY_MANDATORY_SYSTEM_RID => "System",
                >= NativeMethods.SECURITY_MANDATORY_HIGH_RID => "High",
                >= NativeMethods.SECURITY_MANDATORY_MEDIUM_RID => "Medium",
                >= NativeMethods.SECURITY_MANDATORY_LOW_RID => "Low",
                _ => "Untrusted"
            };
        }
        catch
        {
            return "Unknown";
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            if (tokenHandle != IntPtr.Zero) NativeMethods.CloseHandle(tokenHandle);
        }
    }

    public static string GetProcessUser(IntPtr processHandle)
    {
        IntPtr tokenHandle = IntPtr.Zero;
        IntPtr buffer = IntPtr.Zero;

        try
        {
            if (!NativeMethods.OpenProcessToken(processHandle,
                NativeMethods.TOKEN_QUERY, out tokenHandle))
                return "Unknown";

            NativeMethods.GetTokenInformation(tokenHandle,
                NativeMethods.TokenUser, IntPtr.Zero, 0, out int length);

            if (length == 0) return "Unknown";

            buffer = Marshal.AllocHGlobal(length);

            if (!NativeMethods.GetTokenInformation(tokenHandle,
                NativeMethods.TokenUser, buffer, length, out _))
                return "Unknown";

            IntPtr sidPtr = Marshal.ReadIntPtr(buffer);

            var name = new StringBuilder(256);
            var domain = new StringBuilder(256);
            uint nameLen = 256, domainLen = 256;

            if (NativeMethods.LookupAccountSidW(null, sidPtr, name, ref nameLen,
                domain, ref domainLen, out _))
            {
                return $"{domain}\\{name}";
            }

            return "Unknown";
        }
        catch
        {
            return "Unknown";
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            if (tokenHandle != IntPtr.Zero) NativeMethods.CloseHandle(tokenHandle);
        }
    }

    public static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }
}
using DLLHijackHunter.Models;
using System.Diagnostics;

namespace DLLHijackHunter.Canary;

public static class TriggerExecutor
{
    /// <summary>
    /// Trigger the execution context so it loads the canary DLL.
    /// </summary>
    public static async Task<bool> TriggerAsync(HijackCandidate candidate, int timeoutSeconds = 15)
    {
        try
        {
            switch (candidate.Trigger)
            {
                case TriggerType.Service:
                    return await TriggerService(candidate.TriggerIdentifier, timeoutSeconds);

                case TriggerType.ScheduledTask:
                    return await TriggerScheduledTask(candidate.TriggerIdentifier, timeoutSeconds);

                case TriggerType.COM:
                    return await TriggerCOM(candidate.TriggerIdentifier, timeoutSeconds);

                case TriggerType.Startup:
                case TriggerType.RunKey:
                    // Can't easily trigger — would need logoff/logon or reboot
                    return false;

                default:
                    return false;
            }
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> TriggerService(string serviceName, int timeoutSeconds)
    {
        try
        {
            // Stop the service
            await RunProcess("sc.exe", $"stop \"{serviceName}\"", 10);
            await Task.Delay(2000);

            // Start the service
            var (exitCode, _) = await RunProcess("sc.exe", $"start \"{serviceName}\"", timeoutSeconds);
            await Task.Delay(3000); // wait for DLL loading

            return exitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> TriggerScheduledTask(string taskPath, int timeoutSeconds)
    {
        try
        {
            var (exitCode, _) = await RunProcess("schtasks.exe",
                $"/run /tn \"{taskPath}\"", timeoutSeconds);
            await Task.Delay(3000);
            return exitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> TriggerCOM(string clsid, int timeoutSeconds)
    {
        try
        {
            // Use PowerShell to instantiate the COM object
            string psCommand = $"[Activator]::CreateInstance(" +
                $"[Type]::GetTypeFromCLSID('{clsid}'))";

            var (exitCode, _) = await RunProcess("powershell.exe",
                $"-NoProfile -Command \"{psCommand}\"", timeoutSeconds);
            await Task.Delay(2000);
            return exitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<(int exitCode, string output)> RunProcess(
        string fileName, string arguments, int timeoutSeconds)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using var proc = Process.Start(psi);
        if (proc == null) return (-1, "");

        string output = await proc.StandardOutput.ReadToEndAsync();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        try
        {
            await proc.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(); } catch { }
            return (-1, output);
        }

        return (proc.ExitCode, output);
    }
}
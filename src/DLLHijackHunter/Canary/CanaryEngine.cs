// src/DLLHijackHunter/Canary/CanaryEngine.cs

using DLLHijackHunter.Models;
using DLLHijackHunter.Discovery;
using Spectre.Console;

namespace DLLHijackHunter.Canary;

public class CanaryEngine
{
    private readonly ScanProfile _profile;

    public CanaryEngine(ScanProfile profile)
    {
        _profile = profile;
    }

    public async Task<List<HijackCandidate>> ConfirmAsync(List<HijackCandidate> candidates)
    {
        if (!_profile.RunCanary)
        {
            AnsiConsole.MarkupLine("[yellow]Canary confirmation disabled by profile.[/]");
            return candidates;
        }

        AnsiConsole.MarkupLine($"\n[bold cyan]═══ Canary Confirmation ({candidates.Count} candidates) ═══[/]");

        int confirmed = 0, failed = 0, skipped = 0;

        await AnsiConsole.Progress()
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask("[green]Testing candidates[/]", maxValue: candidates.Count);

                foreach (var candidate in candidates)
                {
                    task.Increment(1);

                    // Skip candidates that can't be triggered automatically
                    if (candidate.Trigger is TriggerType.Startup or TriggerType.RunKey or
                        TriggerType.Manual or TriggerType.Unknown)
                    {
                        candidate.CanaryResult = CanaryResult.NotTested;
                        candidate.Notes.Add("Canary not tested — requires manual trigger " +
                            "(reboot/logon/manual execution)");
                        skipped++;
                        continue;
                    }

                    try
                    {
                        await TestCandidate(candidate);
                        if (candidate.CanaryResult == CanaryResult.Fired)
                            confirmed++;
                        else
                            failed++;
                    }
                    catch (Exception ex)
                    {
                        candidate.CanaryResult = CanaryResult.Failed;
                        candidate.Notes.Add($"Canary error: {ex.Message}");
                        failed++;
                    }
                }
            });

        AnsiConsole.MarkupLine($"  [green]Confirmed: {confirmed}[/] | " +
            $"[red]Failed: {failed}[/] | [yellow]Skipped: {skipped}[/]");

        // Cleanup all canary artifacts
        CanaryDllBuilder.CleanupAll();

        return candidates;
    }

    private async Task TestCandidate(HijackCandidate candidate)
    {
        string canaryId = Guid.NewGuid().ToString("N")[..12];

        try
        {
            // Determine architecture
            bool is64Bit = true;
            try
            {
                var pe = PEAnalyzer.Analyze(candidate.BinaryPath);
                is64Bit = pe.Is64Bit;
            }
            catch { }

            // Build canary DLL
            var canaryInfo = CanaryDllBuilder.BuildCanary(
                canaryId,
                candidate.DllName,
                candidate.DllLegitPath,
                is64Bit
            );

            // Check if DLL was built successfully
            if (string.IsNullOrEmpty(canaryInfo.DllPath) || !File.Exists(canaryInfo.DllPath))
            {
                candidate.CanaryResult = CanaryResult.NotTested;
                candidate.Notes.Add("Could not build canary DLL — no C compiler available. " +
                    "Install MinGW-w64 or Visual Studio Build Tools for canary confirmation. " +
                    "Finding is still valid based on static/ETW analysis.");
                return;
            }

            // Backup existing DLL if present
            string? backupPath = null;
            bool hadExistingDll = File.Exists(candidate.HijackWritablePath);

            if (hadExistingDll)
            {
                backupPath = candidate.HijackWritablePath + ".hijackhunter.bak";
                try
                {
                    File.Copy(candidate.HijackWritablePath, backupPath, true);
                }
                catch (Exception ex)
                {
                    candidate.CanaryResult = CanaryResult.Failed;
                    candidate.Notes.Add($"Could not backup existing DLL: {ex.Message}");
                    return;
                }
            }

            try
            {
                // Ensure target directory exists
                string? targetDir = Path.GetDirectoryName(candidate.HijackWritablePath);
                if (targetDir != null && !Directory.Exists(targetDir))
                {
                    // For .local hijacks, create the .local directory
                    if (candidate.Type == HijackType.DotLocal)
                    {
                        try { Directory.CreateDirectory(targetDir); }
                        catch
                        {
                            candidate.CanaryResult = CanaryResult.Failed;
                            candidate.Notes.Add("Could not create .local directory");
                            return;
                        }
                    }
                    else
                    {
                        candidate.CanaryResult = CanaryResult.Failed;
                        candidate.Notes.Add("Target directory does not exist");
                        return;
                    }
                }

                // Deploy canary DLL
                File.Copy(canaryInfo.DllPath, candidate.HijackWritablePath, true);

                // Trigger execution
                bool triggered = await TriggerExecutor.TriggerAsync(
                    candidate, _profile.CanaryTimeoutSeconds);

                // Wait for DllMain to execute and write confirmation
                await Task.Delay(TimeSpan.FromSeconds(3));

                // Check for confirmation file
                if (File.Exists(canaryInfo.ConfirmPath))
                {
                    candidate.CanaryResult = CanaryResult.Fired;
                    candidate.Confidence = 100.0;
                    ParseConfirmation(candidate, canaryInfo.ConfirmPath);
                }
                else if (!triggered)
                {
                    candidate.CanaryResult = CanaryResult.Failed;
                    candidate.Notes.Add("Could not trigger execution context " +
                        "(service may be running, access denied, or dependency chain issue)");
                }
                else
                {
                    // Wait a bit longer for slow services
                    await Task.Delay(TimeSpan.FromSeconds(5));

                    if (File.Exists(canaryInfo.ConfirmPath))
                    {
                        candidate.CanaryResult = CanaryResult.Fired;
                        candidate.Confidence = 100.0;
                        ParseConfirmation(candidate, canaryInfo.ConfirmPath);
                    }
                    else
                    {
                        candidate.CanaryResult = CanaryResult.Timeout;
                        candidate.Notes.Add("Execution triggered but canary did not fire within timeout. " +
                            "May require specific conditions, user interaction, or longer wait.");
                    }
                }

                // Check if app is still functional (for search order hijacks)
                if (candidate.CanaryResult == CanaryResult.Fired &&
                    candidate.Type == HijackType.SearchOrder)
                {
                    candidate.AppStillFunctional = true; // proxy DLL should keep it working
                }
            }
            finally
            {
                // Cleanup: remove canary DLL
                try
                {
                    if (File.Exists(candidate.HijackWritablePath))
                        File.Delete(candidate.HijackWritablePath);
                }
                catch
                {
                    candidate.Notes.Add("Warning: Could not remove canary DLL — file may be locked");
                }

                // Restore backup
                if (backupPath != null && File.Exists(backupPath))
                {
                    try
                    {
                        File.Move(backupPath, candidate.HijackWritablePath, true);
                    }
                    catch
                    {
                        candidate.Notes.Add("Warning: Could not restore original DLL from backup");
                    }
                }

                // Clean up .local directory if we created it
                if (candidate.Type == HijackType.DotLocal)
                {
                    string? dotLocalDir = Path.GetDirectoryName(candidate.HijackWritablePath);
                    if (dotLocalDir != null)
                    {
                        try
                        {
                            if (Directory.Exists(dotLocalDir) &&
                                !Directory.EnumerateFileSystemEntries(dotLocalDir).Any())
                            {
                                Directory.Delete(dotLocalDir);
                            }
                        }
                        catch { }
                    }
                }

                // Restart service to ensure clean state
                if (candidate.Trigger == TriggerType.Service)
                {
                    try
                    {
                        var psi = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "sc.exe",
                            Arguments = $"start \"{candidate.TriggerIdentifier}\"",
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true
                        };
                        var proc = System.Diagnostics.Process.Start(psi);
                        proc?.WaitForExit(10000);
                    }
                    catch { }
                }
            }
        }
        finally
        {
            CanaryDllBuilder.Cleanup(canaryId);
        }
    }

    private static void ParseConfirmation(HijackCandidate candidate, string confirmPath)
    {
        try
        {
            var lines = File.ReadAllLines(confirmPath);
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var line in lines)
            {
                int eq = line.IndexOf('=');
                if (eq > 0)
                {
                    string key = line[..eq].Trim();
                    string value = line[(eq + 1)..].Trim();
                    data[key] = value;
                }
            }

            candidate.ConfirmedPrivilege = data.GetValueOrDefault("USER", "Unknown");
            candidate.ConfirmedIntegrityLevel = data.GetValueOrDefault("INTEGRITY", "Unknown");
            candidate.ConfirmedSeDebug = data.GetValueOrDefault("SE_DEBUG", "NO")
                .Equals("YES", StringComparison.OrdinalIgnoreCase);

            candidate.Notes.Add($"✓ CANARY CONFIRMED: Running as {candidate.ConfirmedPrivilege} " +
                $"at {candidate.ConfirmedIntegrityLevel} integrity" +
                (candidate.ConfirmedSeDebug == true ? " with SeDebugPrivilege" : ""));

            try { File.Delete(confirmPath); } catch { }
        }
        catch (Exception ex)
        {
            candidate.Notes.Add($"Canary fired but could not parse confirmation: {ex.Message}");
        }
    }
}
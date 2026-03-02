// src/DLLHijackHunter/Discovery/ETWDiscoveryEngine.cs

using DLLHijackHunter.Models;
using DLLHijackHunter.Native;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Spectre.Console;
using System.Collections.Concurrent;

namespace DLLHijackHunter.Discovery;

public class ETWDiscoveryEngine
{
    private readonly ScanProfile _profile;
    private readonly ConcurrentDictionary<int, ProcessContext> _processes = new();
    private readonly ConcurrentBag<HijackCandidate> _candidates = new();
    private readonly ConcurrentDictionary<string, byte> _failedLookups = new();

    public ETWDiscoveryEngine(ScanProfile profile)
    {
        _profile = profile;
    }

    public async Task<List<HijackCandidate>> DiscoverAsync()
    {
        if (!(TraceEventSession.IsElevated() ?? false))
        {
            AnsiConsole.MarkupLine("[red]ETW requires elevation. Skipping runtime discovery.[/]");
            return new List<HijackCandidate>();
        }

        // Kill any leftover session from previous run
        try
        {
            var existingSession = TraceEventSession.GetActiveSession("DLLHijackHunter-Trace");
            existingSession?.Stop();
            existingSession?.Dispose();
        }
        catch { }

        AnsiConsole.MarkupLine("[yellow]Starting ETW runtime discovery...[/]");

        using var session = new TraceEventSession("DLLHijackHunter-Trace");

        try
        {
            session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.ImageLoad |
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.FileIO
            );

            session.Source.Kernel.ProcessStart += OnProcessStart;
            session.Source.Kernel.ImageLoad += OnImageLoad;
            session.Source.Kernel.FileIOCreate += OnFileIOCreate;

            var processingTask = Task.Run(() =>
            {
                try { session.Source.Process(); }
                catch { /* session stopped */ }
            });

            await AnsiConsole.Status().StartAsync("[bold yellow]ETW Tracing...[/]", async ctx =>
            {
                if (_profile.TriggerServices)
                {
                    ctx.Status("[yellow]Triggering services...[/]");
                    await TriggerServices();
                }

                if (_profile.TriggerScheduledTasks)
                {
                    ctx.Status("[yellow]Triggering scheduled tasks...[/]");
                    await TriggerScheduledTasks();
                }

                ctx.Status($"[yellow]Collecting ETW events for {_profile.ETWDurationSeconds}s...[/]");
                await Task.Delay(TimeSpan.FromSeconds(_profile.ETWDurationSeconds));
            });

            session.Stop();
            AnsiConsole.MarkupLine($"  [green]ETW captured {_candidates.Count} candidates, " +
                $"{_failedLookups.Count} failed DLL lookups[/]");
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]ETW error: {ex.Message}[/]");
            try { session.Stop(); } catch { }
        }

        return _candidates.ToList();
    }

    /// <summary>
    /// Enrich ETW candidates with static context data (RunAsAccount, Trigger, etc.)
    /// </summary>
    public void EnrichWithStaticData(List<HijackCandidate> etwCandidates,
        List<ExecutionContext> staticContexts)
    {
        var contextByPath = staticContexts
            .GroupBy(c => c.BinaryPath, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.OrderByDescending(c => GetPriority(c)).First(),
                StringComparer.OrdinalIgnoreCase);

        var contextByName = staticContexts
            .GroupBy(c => Path.GetFileName(c.BinaryPath).ToLowerInvariant())
            .ToDictionary(g => g.Key, g => g.OrderByDescending(c => GetPriority(c)).First(),
                StringComparer.OrdinalIgnoreCase);

        foreach (var candidate in etwCandidates)
        {
            ExecutionContext? ctx = null;

            // Try exact path match first
            if (!string.IsNullOrEmpty(candidate.BinaryPath))
                contextByPath.TryGetValue(candidate.BinaryPath, out ctx);

            // Fall back to filename match
            if (ctx == null && !string.IsNullOrEmpty(candidate.BinaryPath))
            {
                string name = Path.GetFileName(candidate.BinaryPath).ToLowerInvariant();
                contextByName.TryGetValue(name, out ctx);
            }

            if (ctx != null)
            {
                if (string.IsNullOrEmpty(candidate.RunAsAccount) || candidate.RunAsAccount == "Unknown")
                    candidate.RunAsAccount = ctx.RunAsAccount;
                if (candidate.Trigger == TriggerType.Unknown)
                {
                    candidate.Trigger = ctx.TriggerType;
                    candidate.TriggerIdentifier = ctx.TriggerIdentifier;
                }
                if (string.IsNullOrEmpty(candidate.ServiceStartType))
                    candidate.ServiceStartType = ctx.StartType;
                candidate.SurvivesReboot = ctx.IsAutoStart;
            }
        }
    }

    private void OnProcessStart(ProcessTraceData data)
    {
        try
        {
            var ctx = new ProcessContext
            {
                Pid = data.ProcessID,
                ImagePath = data.ImageFileName ?? "",
                CommandLine = data.CommandLine ?? ""
            };

            // Enrich with token info if possible
            try
            {
                using var proc = System.Diagnostics.Process.GetProcessById(data.ProcessID);
                ctx.TokenUser = TokenHelper.GetProcessUser(proc.Handle);
                ctx.IntegrityLevel = TokenHelper.GetProcessIntegrityLevel(proc.Handle);
            }
            catch
            {
                ctx.TokenUser = "Unknown";
                ctx.IntegrityLevel = "Unknown";
            }

            _processes[data.ProcessID] = ctx;
        }
        catch { }
    }

    private void OnImageLoad(ImageLoadTraceData data)
    {
        try
        {
            string fileName = data.FileName ?? "";
            if (!fileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) return;

            if (_processes.TryGetValue(data.ProcessID, out var ctx))
            {
                ctx.LoadedDlls.Add(fileName);

                string dllName = Path.GetFileName(fileName);
                string? actualDir = Path.GetDirectoryName(fileName);

                if (actualDir != null &&
                    !actualDir.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase) &&
                    !actualDir.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                        StringComparison.OrdinalIgnoreCase) &&
                    AclChecker.IsDirectoryWritableByCurrentUser(actualDir))
                {
                    _candidates.Add(new HijackCandidate
                    {
                        BinaryPath = ctx.ImagePath,
                        DllName = dllName,
                        DllLegitPath = fileName,
                        Type = HijackType.SearchOrder,
                        HijackWritablePath = Path.Combine(actualDir, dllName),
                        RunAsAccount = ctx.TokenUser,
                        DiscoverySource = "etw",
                        Notes = { $"DLL loaded from writable directory at runtime (PID {data.ProcessID})" }
                    });
                }
            }
        }
        catch { }
    }

    private void OnFileIOCreate(FileIOCreateTraceData data)
    {
        try
        {
            string fileName = data.FileName ?? "";
            if (!fileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) return;

            if (!File.Exists(fileName))
            {
                string lookupKey = $"{data.ProcessID}|{fileName}";
                if (_failedLookups.TryAdd(lookupKey, 0))
                {
                    string? dir = Path.GetDirectoryName(fileName);
                    if (dir != null && Directory.Exists(dir) &&
                        AclChecker.IsDirectoryWritableByCurrentUser(dir))
                    {
                        string dllName = Path.GetFileName(fileName);
                        string processPath = "";
                        string tokenUser = "Unknown";

                        if (_processes.TryGetValue(data.ProcessID, out var ctx))
                        {
                            processPath = ctx.ImagePath;
                            tokenUser = ctx.TokenUser;
                            ctx.FailedDllLookups.Add(fileName);
                        }

                        _candidates.Add(new HijackCandidate
                        {
                            BinaryPath = processPath,
                            DllName = dllName,
                            DllLegitPath = null,
                            Type = HijackType.Phantom,
                            HijackWritablePath = fileName,
                            RunAsAccount = tokenUser,
                            DiscoverySource = "etw",
                            Notes =
                            {
                                $"Phantom DLL detected via ETW (PID {data.ProcessID})",
                                $"Process probed {fileName} but file does not exist"
                            }
                        });
                    }
                }
            }
        }
        catch { }
    }

    private async Task TriggerServices()
    {
        try
        {
            var services = ServiceEnumerator.EnumerateServices()
                .Where(s => s.IsAutoStart && s.StartType != "DISABLED")
                .GroupBy(s => s.TriggerIdentifier)
                .Select(g => g.First())
                .Take(100)
                .ToList();

            foreach (var svc in services)
            {
                try
                {
                    var psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "sc.exe",
                        Arguments = $"start \"{svc.TriggerIdentifier}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    var proc = System.Diagnostics.Process.Start(psi);
                    if (proc != null)
                    {
                        using var cts = new CancellationTokenSource(5000);
                        try { await proc.WaitForExitAsync(cts.Token); }
                        catch { try { proc.Kill(); } catch { } }
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private async Task TriggerScheduledTasks()
    {
        try
        {
            var tasks = ScheduledTaskEnumerator.EnumerateScheduledTasks();
            foreach (var task in tasks.Take(30))
            {
                try
                {
                    var psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "schtasks.exe",
                        Arguments = $"/run /tn \"{task.TriggerIdentifier}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    var proc = System.Diagnostics.Process.Start(psi);
                    if (proc != null)
                    {
                        using var cts = new CancellationTokenSource(5000);
                        try { await proc.WaitForExitAsync(cts.Token); }
                        catch { try { proc.Kill(); } catch { } }
                    }
                }
                catch { }
            }
            await Task.Delay(2000);
        }
        catch { }
    }

    private static int GetPriority(ExecutionContext c) => c.TriggerType switch
    {
        TriggerType.Service when c.IsAutoStart => 10,
        TriggerType.Service => 8,
        TriggerType.ScheduledTask => 6,
        TriggerType.Startup => 5,
        _ => 1
    };
}
// src/DLLHijackHunter/Discovery/StaticDiscoveryEngine.cs

using DLLHijackHunter.Models;
using DLLHijackHunter.Native;
using Spectre.Console;

namespace DLLHijackHunter.Discovery;

public class StaticDiscoveryEngine
{
    private readonly ScanProfile _profile;

    private static readonly HashSet<string> PhantomDllDatabase = new(StringComparer.OrdinalIgnoreCase)
    {
        // ─── Classic Windows Phantom DLLs ───
        "wlbsctrl.dll", "wlanhlp.dll", "wlanapi.dll", "dsparse.dll",
        "ualapi.dll", "tsmsisrv.dll", "taborjt.dll", "srvcli.dll",
        "sxs.dll", "ncobjapi.dll", "msdmo.dll", "msfte.dll",
        "windowscodecs.dll", "propsys.dll", "ntmarta.dll",
        "edgegdi.dll", "phoneinfo.dll", "IKEEXT.dll",

        // ─── Windows 10/11 Phantom DLLs ───
        "profapi.dll", "fltLib.dll", "wer.dll", "dxgi.dll",
        "d3d11.dll", "d3d12.dll", "vulkan-1.dll",
        "amsi.dll", "clbcatq.dll", "msasn1.dll",
        "dwmapi.dll", "uxtheme.dll", "textinputframework.dll",
        "coreuicomponents.dll", "coremessaging.dll",
        "WptsExtensions.dll", "ondemandconnroutehelper.dll",

        // ─── .NET / CLR Phantom DLLs ───
        "mscoree.dll", "clr.dll", "mscoreei.dll",
        "diasymreader.dll", "dbghelp.dll",

        // ─── Common Application Phantom DLLs ───
        "version.dll", "userenv.dll", "winhttp.dll",
        "httpapi.dll", "crypt32.dll", "cryptsp.dll",
        "cryptbase.dll", "gpapi.dll", "dpapi.dll",
        "logoncli.dll", "samcli.dll", "netutils.dll",
        "wkscli.dll", "BrowserSvc.dll", "FwRemoteSvr.dll",

        // ─── Service-specific Phantom DLLs ───
        "iertutil.dll", "cabinet.dll", "msftedit.dll",
        "shdocvw.dll", "mshtml.dll", "jscript.dll",
        "vbscript.dll", "scrrun.dll", "scrobj.dll",

        // ─── Printer/Spooler Phantom DLLs ───
        "prnntfy.dll", "spoolss.dll", "win32spl.dll",

        // ─── WMI Phantom DLLs ───
        "wbemcomn.dll", "wbemsvc.dll", "fastprox.dll",
        "wbemprox.dll", "wmiutils.dll",

        // ─── Network Phantom DLLs ───
        "rasadhlp.dll", "fwpuclnt.dll", "nlaapi.dll",
        "winnsi.dll", "iphlpapi.dll", "dhcpcsvc.dll",
        "dhcpcsvc6.dll", "dnsapi.dll",

        // ─── Security Phantom DLLs ───
        "wdigest.dll", "kerberos.dll", "msv1_0.dll",
        "negoexts.dll", "pku2u.dll", "cloudap.dll",
        "schannel.dll", "mswsock.dll",

        // ─── GPU / Display Phantom DLLs ───
        "nvapi64.dll", "nvapi.dll", "amdxc64.dll",
        "igdusc64.dll", "opencl.dll",

        // ─── Task Scheduler Phantom DLLs ───
        "dimsjob.dll", "wmiprop.dll", "schedcli.dll",

        // ─── Windows Update Phantom DLLs ───
        "wuaueng.dll", "wuapi.dll", "wups.dll",

        // ─── Edge / Browser Phantom DLLs ───
        "mso.dll", "riched20.dll"
    };

    public StaticDiscoveryEngine(ScanProfile profile)
    {
        _profile = profile;
    }

    public List<HijackCandidate> Discover()
    {
        var candidates = new List<HijackCandidate>();

        AnsiConsole.Status().Start("[bold yellow]Static Discovery...[/]", ctx =>
        {
            // ─── Enumerate all execution contexts ───
            ctx.Status("[yellow]Enumerating services...[/]");
            var contexts = new List<ExecutionContext>();
            contexts.AddRange(ServiceEnumerator.EnumerateServices());

            ctx.Status("[yellow]Enumerating scheduled tasks...[/]");
            contexts.AddRange(ScheduledTaskEnumerator.EnumerateScheduledTasks());

            ctx.Status("[yellow]Enumerating startup items...[/]");
            contexts.AddRange(StartupItemEnumerator.EnumerateStartupItems());

            if (_profile.TriggerCOM)
            {
                ctx.Status("[yellow]Enumerating COM objects...[/]");
                contexts.AddRange(COMEnumerator.EnumerateCOMObjects());
            }

            AnsiConsole.MarkupLine($"  [green]Found {contexts.Count} execution contexts[/]");

            // ═══ FILTER BY TARGET ═══
            if (!string.IsNullOrEmpty(_profile.TargetPath))
            {
                contexts = FilterByTarget(contexts, _profile.TargetPath);
                AnsiConsole.MarkupLine($"  [yellow]Filtered to target: {contexts.Count} contexts match[/]");

                if (contexts.Count == 0)
                {
                    AnsiConsole.MarkupLine($"[red]No execution contexts found for target: {Markup.Escape(_profile.TargetPath)}[/]");
                    AnsiConsole.MarkupLine($"[dim]Tip: Try using just the filename (e.g., 'app.exe') or a directory path[/]");
                    _lastContexts = new List<ExecutionContext>();
                    return;
                }
            }

            // Store contexts for ETW enrichment later
            _lastContexts = contexts;

            // ─── Deduplicate by binary path ───
            var uniqueBinaries = contexts
                .Where(c => File.Exists(c.BinaryPath))
                .GroupBy(c => c.BinaryPath, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

            AnsiConsole.MarkupLine($"  [green]{uniqueBinaries.Count} unique binaries to analyze[/]");

            if (uniqueBinaries.Count == 0)
            {
                AnsiConsole.MarkupLine($"[yellow]No binaries found to analyze[/]");
                return;
            }

            // ─── Analyze each binary ───
            int analyzed = 0;
            foreach (var (binaryPath, executionContexts) in uniqueBinaries)
            {
                analyzed++;
                if (analyzed % 50 == 0)
                    ctx.Status($"[yellow]Analyzing binary {analyzed}/{uniqueBinaries.Count}...[/]");

                try
                {
                    var peResult = PEAnalyzer.Analyze(binaryPath);
                    if (peResult.AnalysisError != null) continue;

                    // For each imported DLL, check for hijack opportunities
                    foreach (string dll in peResult.AllImportedDlls)
                    {
                        var dllCandidates = AnalyzeDllImport(
                            binaryPath, dll, executionContexts, peResult);
                        candidates.AddRange(dllCandidates);
                    }

                    // Check for phantom DLLs from our database
                    CheckPhantomDlls(binaryPath, executionContexts, peResult, candidates);
                }
                catch { continue; }
            }

            // ─── Check PATH directories for writable entries ───
            ctx.Status("[yellow]Checking PATH directories...[/]");
            CheckWritablePathDirectories();

            AnsiConsole.MarkupLine($"  [green]Generated {candidates.Count} candidates[/]");
        });

        return candidates;
    }

    // Expose for ETW enrichment
    private List<ExecutionContext>? _lastContexts;
    public List<ExecutionContext> GetLastContexts() => _lastContexts ?? new();

    private List<HijackCandidate> AnalyzeDllImport(string binaryPath, string dllName,
        List<ExecutionContext> contexts, PEAnalysisResult peResult)
    {
        var candidates = new List<HijackCandidate>();

        // Find hijackable positions in search order
        var hijackPositions = SearchOrderCalculator.FindHijackablePositions(binaryPath, dllName);

        foreach (var hijackPath in hijackPositions)
        {
            var bestCtx = contexts.OrderByDescending(c => GetContextPriority(c)).First();
            string? legitPath = SearchOrderCalculator.FindActualDllLocation(binaryPath, dllName);

            candidates.Add(new HijackCandidate
            {
                BinaryPath = binaryPath,
                DllName = dllName,
                DllLegitPath = legitPath,
                Type = legitPath == null ? HijackType.Phantom : HijackType.SearchOrder,
                HijackWritablePath = hijackPath,
                Trigger = bestCtx.TriggerType,
                TriggerIdentifier = bestCtx.TriggerIdentifier,
                RunAsAccount = bestCtx.RunAsAccount,
                ServiceStartType = bestCtx.StartType,
                TaskFrequency = bestCtx.RepeatInterval,
                SurvivesReboot = bestCtx.IsAutoStart,
                DiscoverySource = "static"
            });
        }

        // Check for .local redirection opportunity
        string dotLocalDir = binaryPath + ".local";
        string dotLocalDllPath = Path.Combine(dotLocalDir, dllName);
        string? dotLocalParent = Path.GetDirectoryName(binaryPath);

        if (dotLocalParent != null &&
            AclChecker.IsDirectoryWritableByCurrentUser(dotLocalParent) &&
            !Directory.Exists(dotLocalDir))
        {
            var bestCtx = contexts.OrderByDescending(c => GetContextPriority(c)).First();
            candidates.Add(new HijackCandidate
            {
                BinaryPath = binaryPath,
                DllName = dllName,
                DllLegitPath = SearchOrderCalculator.FindActualDllLocation(binaryPath, dllName),
                Type = HijackType.DotLocal,
                HijackWritablePath = dotLocalDllPath,
                Trigger = bestCtx.TriggerType,
                TriggerIdentifier = bestCtx.TriggerIdentifier,
                RunAsAccount = bestCtx.RunAsAccount,
                ServiceStartType = bestCtx.StartType,
                SurvivesReboot = bestCtx.IsAutoStart,
                DiscoverySource = "static",
                Notes = { "Requires creating .local directory and placing DLL inside" }
            });
        }

        return candidates;
    }

    private void CheckPhantomDlls(string binaryPath, List<ExecutionContext> contexts,
        PEAnalysisResult peResult, List<HijackCandidate> candidates)
    {
        foreach (string dll in peResult.AllImportedDlls)
        {
            if (!PhantomDllDatabase.Contains(dll)) continue;

            string? actualLocation = SearchOrderCalculator.FindActualDllLocation(binaryPath, dll);
            if (actualLocation != null) continue;

            string? binaryDir = Path.GetDirectoryName(binaryPath);
            if (binaryDir != null && AclChecker.IsDirectoryWritableByCurrentUser(binaryDir))
            {
                var bestCtx = contexts.OrderByDescending(c => GetContextPriority(c)).First();
                candidates.Add(new HijackCandidate
                {
                    BinaryPath = binaryPath,
                    DllName = dll,
                    DllLegitPath = null,
                    Type = HijackType.Phantom,
                    HijackWritablePath = Path.Combine(binaryDir, dll),
                    Trigger = bestCtx.TriggerType,
                    TriggerIdentifier = bestCtx.TriggerIdentifier,
                    RunAsAccount = bestCtx.RunAsAccount,
                    ServiceStartType = bestCtx.StartType,
                    SurvivesReboot = bestCtx.IsAutoStart,
                    DiscoverySource = "static"
                });
            }
        }
    }

    private void CheckWritablePathDirectories()
    {
        var pathDirs = Environment.GetEnvironmentVariable("PATH")?.Split(';',
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (pathDirs == null) return;

        var writablePaths = new List<string>();
        foreach (var dir in pathDirs)
        {
            if (!Directory.Exists(dir)) continue;
            if (!AclChecker.IsDirectoryWritableByCurrentUser(dir)) continue;
            writablePaths.Add(dir);
        }

        if (writablePaths.Any())
        {
            AnsiConsole.MarkupLine($"  [yellow]⚠ {writablePaths.Count} writable PATH directories found:[/]");
            foreach (var wp in writablePaths.Take(5))
                AnsiConsole.MarkupLine($"    [yellow]• {Markup.Escape(wp)}[/]");
            if (writablePaths.Count > 5)
                AnsiConsole.MarkupLine($"    [dim]... and {writablePaths.Count - 5} more[/]");
        }
    }

    // ═══ NEW: FILTER BY TARGET ═══
    private static List<ExecutionContext> FilterByTarget(List<ExecutionContext> contexts, string target)
    {
        // Expand environment variables in target
        string expandedTarget = Environment.ExpandEnvironmentVariables(target);

        // Check if target is a directory or file
        bool isDirectory = Directory.Exists(expandedTarget);
        bool isFile = File.Exists(expandedTarget);

        if (isFile)
        {
            // Exact file match
            var exactMatches = contexts.Where(c =>
                c.BinaryPath.Equals(expandedTarget, StringComparison.OrdinalIgnoreCase)
            ).ToList();

            if (exactMatches.Any())
            {
                AnsiConsole.MarkupLine($"  [green]✓ Found exact match for: {Markup.Escape(expandedTarget)}[/]");
                return exactMatches;
            }
        }

        if (isDirectory)
        {
            // Directory - match anything under it
            var dirMatches = contexts.Where(c =>
                c.BinaryPath.StartsWith(expandedTarget, StringComparison.OrdinalIgnoreCase)
            ).ToList();

            if (dirMatches.Any())
            {
                AnsiConsole.MarkupLine($"  [green]✓ Found {dirMatches.Count} binaries in: {Markup.Escape(expandedTarget)}[/]");
                return dirMatches;
            }
        }

        // Partial match (filename or path fragment)
        string targetLower = target.ToLowerInvariant();
        var partialMatches = contexts.Where(c =>
        {
            string pathLower = c.BinaryPath.ToLowerInvariant();
            string filenameLower = Path.GetFileName(c.BinaryPath).ToLowerInvariant();

            return pathLower.Contains(targetLower) ||
                   filenameLower.Contains(targetLower) ||
                   filenameLower.Equals(targetLower, StringComparison.OrdinalIgnoreCase);
        }).ToList();

        if (partialMatches.Any())
        {
            AnsiConsole.MarkupLine($"  [green]✓ Found {partialMatches.Count} binaries matching: {Markup.Escape(target)}[/]");
            
            // Show first few matches
            if (partialMatches.Count <= 5)
            {
                foreach (var match in partialMatches)
                    AnsiConsole.MarkupLine($"    [dim]• {Markup.Escape(match.BinaryPath)}[/]");
            }
            else
            {
                foreach (var match in partialMatches.Take(3))
                    AnsiConsole.MarkupLine($"    [dim]• {Markup.Escape(match.BinaryPath)}[/]");
                AnsiConsole.MarkupLine($"    [dim]... and {partialMatches.Count - 3} more[/]");
            }
        }

        return partialMatches;
    }

    private static int GetContextPriority(ExecutionContext ctx) => ctx.TriggerType switch
    {
        TriggerType.Service when ctx.IsAutoStart => 10,
        TriggerType.Service => 8,
        TriggerType.ScheduledTask when ctx.IsAutoStart => 7,
        TriggerType.ScheduledTask => 6,
        TriggerType.Startup => 5,
        TriggerType.RunKey => 4,
        TriggerType.COM => 3,
        TriggerType.WMI => 2,
        _ => 1
    };
}
using DLLHijackHunter.Models;
using DLLHijackHunter.Native;
using Spectre.Console;
using System.Reflection;
using System.Text.Json;

namespace DLLHijackHunter.Discovery;

public class StaticDiscoveryEngine
{
    private readonly ScanProfile _profile;

    private static readonly Lazy<HashSet<string>> PhantomDllDatabase = new(LoadPhantomDlls);

    private static HashSet<string> LoadPhantomDlls()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var assembly = Assembly.GetExecutingAssembly();
            using var stream = assembly.GetManifestResourceStream(
                "DLLHijackHunter.Resources.phantom_dlls.json");
            if (stream == null) return set;

            using var reader = new StreamReader(stream);
            string json = reader.ReadToEnd();

            using var doc = JsonDocument.Parse(json);
            var categories = doc.RootElement.GetProperty("categories");

            foreach (var category in categories.EnumerateObject())
            {
                foreach (var dll in category.Value.EnumerateArray())
                {
                    string? name = dll.GetString();
                    if (name != null) set.Add(name);
                }
            }
        }
        catch
        {
            // Fallback: return empty set if resource loading fails
        }
        return set;
    }

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
            var contexts = new List<DiscoveryContext>();
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

            if (_profile.TriggerAutoElevate)
            {
                ctx.Status("[yellow]Hunting for AutoElevate UAC Bypass binaries...[/]");
                var autoElevateContexts = AutoElevateEnumerator.EnumerateAutoElevateBinaries();
                contexts.AddRange(autoElevateContexts);
                AnsiConsole.MarkupLine($"  [green]Found {autoElevateContexts.Count} AutoElevate binaries[/]");
            }

            // ═══ FILTER BY TARGET ═══
            if (!string.IsNullOrEmpty(_profile.TargetPath))
            {
                contexts = FilterByTarget(contexts, _profile.TargetPath);
                AnsiConsole.MarkupLine($"  [yellow]Filtered to target: {contexts.Count} contexts match[/]");

                if (contexts.Count == 0)
                {
                    AnsiConsole.MarkupLine($"[red]No execution contexts found for target: {Markup.Escape(_profile.TargetPath)}[/]");
                    AnsiConsole.MarkupLine($"[dim]Tip: Try using just the filename (e.g., 'app.exe') or a directory path[/]");
                    _lastContexts = new List<DiscoveryContext>();
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
    private List<DiscoveryContext>? _lastContexts;
    public List<DiscoveryContext> GetLastContexts() => _lastContexts ?? new();

    private List<HijackCandidate> AnalyzeDllImport(string binaryPath, string dllName,
        List<DiscoveryContext> contexts, PEAnalysisResult peResult)
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

        // ═══ AutoElevate Side-Loading Simulation ═══
        // If this is a UACBypass binary and it doesn't protect against CWD loads,
        // an attacker can copy the EXE to a writable folder (e.g. %TEMP%), place
        // a malicious DLL next to it, and execute for a silent UAC bypass.
        var uacCtx = contexts.FirstOrDefault(c => c.TriggerType == TriggerType.UACBypass);
        if (uacCtx != null && !peResult.CallsSetDllDirectory && !peResult.CallsSetDefaultDllDirectories)
        {
            string tempTarget = Path.Combine(Path.GetTempPath(), dllName);
            candidates.Add(new HijackCandidate
            {
                BinaryPath = binaryPath,
                DllName = dllName,
                DllLegitPath = SearchOrderCalculator.FindActualDllLocation(binaryPath, dllName),
                Type = HijackType.SideLoad,
                HijackWritablePath = tempTarget,
                Trigger = TriggerType.UACBypass,
                TriggerIdentifier = "Copy-to-Temp Side-Loading",
                RunAsAccount = uacCtx.RunAsAccount,
                ServiceStartType = "MANUAL",
                IsSimulatedCopyAttack = true,
                SurvivesReboot = false,
                DiscoverySource = "static",
                Notes =
                {
                    "COPY & SIDE-LOAD: Attacker copies this AutoElevate EXE to a writable " +
                    "folder, places the DLL next to it, and executes for a silent UAC bypass."
                }
            });
        }

        return candidates;
    }

    private void CheckPhantomDlls(string binaryPath, List<DiscoveryContext> contexts,
        PEAnalysisResult peResult, List<HijackCandidate> candidates)
    {
        foreach (string dll in peResult.AllImportedDlls)
        {
            if (!PhantomDllDatabase.Value.Contains(dll)) continue;

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
    private static List<DiscoveryContext> FilterByTarget(List<DiscoveryContext> contexts, string target)
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

    private static int GetContextPriority(DiscoveryContext ctx) => ctx.TriggerType switch
    {
        TriggerType.Service when ctx.IsAutoStart => 10,
        TriggerType.Service => 8,
        TriggerType.UACBypass => 8,
        TriggerType.ScheduledTask when ctx.IsAutoStart => 7,
        TriggerType.ScheduledTask => 6,
        TriggerType.Startup => 5,
        TriggerType.RunKey => 4,
        TriggerType.COM => 3,
        TriggerType.WMI => 2,
        _ => 1
    };
}
// src/DLLHijackHunter/Program.cs

using DLLHijackHunter.Models;
using DLLHijackHunter.Discovery;
using DLLHijackHunter.Filters;
using DLLHijackHunter.Canary;
using DLLHijackHunter.Scoring;
using DLLHijackHunter.Reporting;
using Spectre.Console;
using System.CommandLine;
using System.Diagnostics;
using System.Security.Principal;

namespace DLLHijackHunter;

public class Program
{
    public static async Task<int> Main(string[] args)
    {
        // Global exception handlers
        AppDomain.CurrentDomain.UnhandledException += (sender, e) =>
        {
            try
            {
                AnsiConsole.MarkupLine($"[red]Fatal error: {Markup.Escape(e.ExceptionObject?.ToString() ?? "Unknown")}[/]");
            }
            catch
            {
                Console.Error.WriteLine($"Fatal error: {e.ExceptionObject}");
            }
            Environment.Exit(1);
        };

        TaskScheduler.UnobservedTaskException += (sender, e) =>
        {
            e.SetObserved();
        };

        var rootCommand = new RootCommand("DLLHijackHunter — Automated DLL Hijacking Detection")
        {
            TreatUnmatchedTokensAsErrors = true
        };

        var profileOption = new Option<string>(
            aliases: new[] { "--profile", "-p" },
            description: "Scan profile: aggressive, strict, safe, redteam",
            getDefaultValue: () => "aggressive");

        var outputOption = new Option<string?>(
            aliases: new[] { "--output", "-o" },
            description: "Output file path (auto-detects format from extension)");

        var formatOption = new Option<string>(
            aliases: new[] { "--format", "-f" },
            description: "Output format: console, json, html",
            getDefaultValue: () => "console");

        var minConfidenceOption = new Option<double>(
            aliases: new[] { "--min-confidence" },
            description: "Minimum confidence threshold (0-100)",
            getDefaultValue: () => 20);

        var noCanaryOption = new Option<bool>(
            aliases: new[] { "--no-canary" },
            description: "Disable canary confirmation (safe for production)");

        var noEtwOption = new Option<bool>(
            aliases: new[] { "--no-etw" },
            description: "Disable ETW runtime discovery");

        var confirmedOnlyOption = new Option<bool>(
            aliases: new[] { "--confirmed-only" },
            description: "Only show canary-confirmed findings");

        var verboseOption = new Option<bool>(
            aliases: new[] { "--verbose", "-v" },
            description: "Verbose output");

        var targetOption = new Option<string?>(
            aliases: new[] { "--target", "-t" },
            description: "Target specific binary, directory, or filename (e.g., 'notepad.exe', 'C:\\MyApp', 'C:\\MyApp\\app.exe')");

        var logFileOption = new Option<string?>(
            aliases: new[] { "--log-file" },
            description: "Write scan log to file for diagnostic purposes");

        rootCommand.AddOption(profileOption);
        rootCommand.AddOption(outputOption);
        rootCommand.AddOption(formatOption);
        rootCommand.AddOption(minConfidenceOption);
        rootCommand.AddOption(noCanaryOption);
        rootCommand.AddOption(noEtwOption);
        rootCommand.AddOption(confirmedOnlyOption);
        rootCommand.AddOption(verboseOption);
        rootCommand.AddOption(targetOption);
        rootCommand.AddOption(logFileOption);

        rootCommand.SetHandler(async (ctx) =>
        {
            var profile = ctx.ParseResult.GetValueForOption(profileOption)!;
            var output = ctx.ParseResult.GetValueForOption(outputOption);
            var format = ctx.ParseResult.GetValueForOption(formatOption)!;
            var minConf = ctx.ParseResult.GetValueForOption(minConfidenceOption);
            var noCanary = ctx.ParseResult.GetValueForOption(noCanaryOption);
            var noEtw = ctx.ParseResult.GetValueForOption(noEtwOption);
            var confirmedOnly = ctx.ParseResult.GetValueForOption(confirmedOnlyOption);
            var verbose = ctx.ParseResult.GetValueForOption(verboseOption);
            var target = ctx.ParseResult.GetValueForOption(targetOption);
            var logFile = ctx.ParseResult.GetValueForOption(logFileOption);

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
                AnsiConsole.MarkupLine("\n[yellow]Cancellation requested... cleaning up.[/]");
            };

            await RunScan(profile, output, format, minConf, noCanary, noEtw,
                confirmedOnly, verbose, target, logFile, cts.Token);
        });

        return await rootCommand.InvokeAsync(args);
    }

    private static async Task RunScan(string profileName, string? outputPath, string format,
        double minConfidence, bool noCanary, bool noEtw, bool confirmedOnly, bool verbose,
        string? target, string? logFile, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();

        // ─── Initialize logger ───
        ScanLogger.Initialize(logFile, verbose);

        try
        {

        // ─── Banner ───
        BannerConstants.PrintBanner();
        AnsiConsole.MarkupLine($"[dim]v1.0.0 | {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC[/]\n");

        // ─── Elevation check ───
        bool isElevated;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            isElevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            isElevated = false;
        }

        if (!isElevated)
        {
            AnsiConsole.MarkupLine("[yellow]⚠ Running without elevation. " +
                "Some features (ETW, service triggers, canary) require admin.[/]");
        }

        // ─── Build profile ───
        var profile = ScanProfile.FromName(profileName);
        profile.MinConfidence = minConfidence;
        profile.Verbose = verbose;
        if (noCanary) profile.RunCanary = false;
        if (noEtw) profile.RunETW = false;
        if (confirmedOnly) profile.ConfirmedOnly = true;
        if (outputPath != null) profile.OutputPath = outputPath;
        profile.OutputFormat = format;

        if (!string.IsNullOrEmpty(target))
        {
            profile.TargetPath = target;
        }

        AnsiConsole.MarkupLine($"[bold]Profile:[/] {profile.Name}");
        AnsiConsole.MarkupLine($"[bold]Mode:[/] Static" +
            (profile.RunETW ? " + ETW" : "") +
            (profile.RunCanary ? " + Canary" : ""));
        AnsiConsole.MarkupLine($"[bold]Min Confidence:[/] {profile.MinConfidence}%");
        AnsiConsole.MarkupLine($"[bold]Elevated:[/] {(isElevated ? "[green]Yes[/]" : "[yellow]No[/]")}");
        
        if (!string.IsNullOrEmpty(profile.TargetPath))
        {
            AnsiConsole.MarkupLine($"[bold]Target:[/] {Markup.Escape(profile.TargetPath)}");
        }
        
        AnsiConsole.WriteLine();

        // ═══════════════════════════════════════════════
        //  PHASE 1: DISCOVERY
        // ═══════════════════════════════════════════════
        AnsiConsole.MarkupLine("[bold cyan]═══ Phase 1: Discovery ═══[/]");

        // Static discovery
        var staticEngine = new StaticDiscoveryEngine(profile);
        var candidates = staticEngine.Discover();

        // ETW runtime discovery
        if (profile.RunETW && isElevated)
        {
            var etwEngine = new ETWDiscoveryEngine(profile);
            var etwCandidates = await etwEngine.DiscoverAsync(cancellationToken);

            // Enrich ETW candidates with static context data
            var staticContexts = staticEngine.GetLastContexts();
            etwEngine.EnrichWithStaticData(etwCandidates, staticContexts);

            // Merge ETW candidates (avoid duplicates)
            var existing = new HashSet<string>(
                candidates.Select(c => $"{c.BinaryPath}|{c.DllName}|{c.HijackWritablePath}"),
                StringComparer.OrdinalIgnoreCase);

            int newFromEtw = 0;
            foreach (var ec in etwCandidates)
            {
                string key = $"{ec.BinaryPath}|{ec.DllName}|{ec.HijackWritablePath}";
                if (existing.Add(key))
                {
                    candidates.Add(ec);
                    newFromEtw++;
                }
            }

            AnsiConsole.MarkupLine($"  [green]ETW added {newFromEtw} new candidates " +
                $"(total: {candidates.Count})[/]");
        }
        else if (profile.RunETW && !isElevated)
        {
            AnsiConsole.MarkupLine("[yellow]  Skipping ETW (requires elevation)[/]");
        }

        int totalDiscovered = candidates.Count;

        if (totalDiscovered == 0)
        {
            AnsiConsole.MarkupLine("\n[yellow]No candidates discovered.[/]");
            
            if (!string.IsNullOrEmpty(profile.TargetPath))
            {
                AnsiConsole.MarkupLine($"[yellow]No DLL hijack candidates found for target: {Markup.Escape(profile.TargetPath)}[/]");
                AnsiConsole.MarkupLine($"[dim]This could mean:[/]");
                AnsiConsole.MarkupLine($"[dim]  • The target is well-hardened (good!)[/]");
                AnsiConsole.MarkupLine($"[dim]  • The target wasn't found in execution contexts[/]");
                AnsiConsole.MarkupLine($"[dim]  • Try running with elevated privileges[/]");
            }
            else
            {
                AnsiConsole.MarkupLine("[yellow]This may indicate a very hardened system or insufficient permissions.[/]");
            }
            
            stopwatch.Stop();
            return;
        }

        // ═══════════════════════════════════════════════
        //  PHASE 2: FILTER PIPELINE
        // ═══════════════════════════════════════════════
        AnsiConsole.MarkupLine("\n[bold cyan]═══ Phase 2: Filter Pipeline ═══[/]");

        var pipeline = new FilterPipeline(profile);
        candidates = pipeline.Process(candidates);

        int afterFilters = candidates.Count;
        int eliminated = totalDiscovered - afterFilters;

        if (afterFilters == 0)
        {
            AnsiConsole.MarkupLine("\n[yellow]All candidates eliminated by filters. " +
                "No hijackable DLLs found.[/]");
            stopwatch.Stop();

            var emptyResult = new ScanResult
            {
                ScanDate = DateTime.UtcNow,
                ScanMode = "Static" + (profile.RunETW ? " + ETW" : ""),
                ProfileUsed = profile.Name,
                ScanDuration = stopwatch.Elapsed,
                TotalCandidatesDiscovered = totalDiscovered,
                EliminatedByHardGates = eliminated
            };

            await GenerateOutput(emptyResult, format, outputPath);
            return;
        }

        // ═══════════════════════════════════════════════
        //  PHASE 3: CANARY CONFIRMATION
        // ═══════════════════════════════════════════════
        if (profile.RunCanary && isElevated)
        {
            AnsiConsole.MarkupLine("\n[bold cyan]═══ Phase 3: Canary Confirmation ═══[/]");

            var canaryEngine = new CanaryEngine(profile);
            candidates = await canaryEngine.ConfirmAsync(candidates, cancellationToken);
        }
        else if (profile.RunCanary && !isElevated)
        {
            AnsiConsole.MarkupLine("\n[yellow]Skipping canary confirmation (requires elevation)[/]");
            foreach (var c in candidates)
            {
                c.CanaryResult = CanaryResult.NotTested;
                c.Notes.Add("Canary not tested — requires elevation");
            }
        }

        // ═══════════════════════════════════════════════
        //  PHASE 4: SCORING & REPORTING
        // ═══════════════════════════════════════════════
        AnsiConsole.MarkupLine("\n[bold cyan]═══ Phase 4: Scoring ═══[/]");

        var scorer = new TieredScorer();
        scorer.ScoreAll(candidates);

        // Filter by minimum confidence
        candidates = candidates
            .Where(c => c.Confidence >= profile.MinConfidence)
            .OrderByDescending(c => c.FinalScore)
            .ToList();

        if (profile.ConfirmedOnly)
        {
            candidates = candidates
                .Where(c => c.CanaryResult == CanaryResult.Fired)
                .ToList();
        }

        stopwatch.Stop();

        // Build scan result
        var scanResult = new ScanResult
        {
            ScanDate = DateTime.UtcNow,
            ScanMode = "Static" + (profile.RunETW ? " + ETW" : "") +
                      (profile.RunCanary ? " + Canary" : ""),
            ProfileUsed = profile.Name,
            ScanDuration = stopwatch.Elapsed,
            TotalCandidatesDiscovered = totalDiscovered,
            EliminatedByHardGates = eliminated,
            SurvivedSoftGates = afterFilters,
            Confirmed = candidates.Where(c => c.Tier == ConfidenceTier.Confirmed).ToList(),
            High = candidates.Where(c => c.Tier == ConfidenceTier.High).ToList(),
            Medium = candidates.Where(c => c.Tier == ConfidenceTier.Medium).ToList(),
            Low = candidates.Where(c => c.Tier == ConfidenceTier.Low).ToList()
        };

        await GenerateOutput(scanResult, format, outputPath);

        AnsiConsole.MarkupLine($"\n[bold green]Scan complete in {stopwatch.Elapsed:mm\\:ss}[/]");
        AnsiConsole.MarkupLine($"[bold]Findings: {scanResult.TotalFindings}[/] " +
            $"([red]{scanResult.Confirmed.Count} confirmed[/] | " +
            $"[orange1]{scanResult.High.Count} high[/] | " +
            $"[yellow]{scanResult.Medium.Count} medium[/] | " +
            $"[grey]{scanResult.Low.Count} low[/])");
        }
        finally
        {
            ScanLogger.Dispose();
        }
    }

    private static async Task GenerateOutput(ScanResult scanResult, string format, string? outputPath)
    {
        string effectiveFormat = format;
        if (outputPath != null)
        {
            string ext = Path.GetExtension(outputPath).ToLowerInvariant();
            effectiveFormat = ext switch
            {
                ".json" => "json",
                ".html" or ".htm" => "html",
                _ => format
            };
        }

        switch (effectiveFormat)
        {
            case "json":
                string jsonPath = outputPath ??
                    $"hijackhunter_report_{DateTime.Now:yyyyMMdd_HHmmss}.json";
                await ReportGenerator.GenerateJsonReport(scanResult, jsonPath);
                break;

            case "html":
                string htmlPath = outputPath ??
                    $"hijackhunter_report_{DateTime.Now:yyyyMMdd_HHmmss}.html";
                await ReportGenerator.GenerateHtmlReport(scanResult, htmlPath);
                break;

            default:
                ReportGenerator.GenerateConsoleReport(scanResult);
                break;
        }

        // Always write JSON alongside console output for record-keeping
        if (effectiveFormat == "console" && scanResult.TotalFindings > 0)
        {
            string autoJsonPath = $"hijackhunter_{DateTime.Now:yyyyMMdd_HHmmss}.json";
            await ReportGenerator.GenerateJsonReport(scanResult, autoJsonPath);
        }
    }
}
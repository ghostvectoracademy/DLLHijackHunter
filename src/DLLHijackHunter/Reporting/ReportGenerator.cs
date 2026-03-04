// src/DLLHijackHunter/Reporting/ReportGenerator.cs

using DLLHijackHunter.Models;
using Spectre.Console;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DLLHijackHunter.Reporting;

public static class ReportGenerator
{
    public static void GenerateConsoleReport(ScanResult result)
    {
        AnsiConsole.Clear();
        BannerConstants.PrintBanner();
        AnsiConsole.WriteLine();

        // Summary table
        var summaryTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("[bold]Property[/]")
            .AddColumn("[bold]Value[/]");

        summaryTable.AddRow("Hostname", result.Hostname);
        summaryTable.AddRow("OS Version", result.OSVersion);
        summaryTable.AddRow("Scan Date", result.ScanDate.ToString("yyyy-MM-dd HH:mm:ss UTC"));
        summaryTable.AddRow("Scan Mode", result.ScanMode);
        summaryTable.AddRow("Profile", result.ProfileUsed);
        summaryTable.AddRow("Duration", result.ScanDuration.ToString(@"mm\:ss"));
        summaryTable.AddRow("Total Candidates", result.TotalCandidatesDiscovered.ToString());
        summaryTable.AddRow("Eliminated (Hard Gates)", result.EliminatedByHardGates.ToString());
        summaryTable.AddRow("[green bold]Total Findings[/]", $"[green bold]{result.TotalFindings}[/]");

        AnsiConsole.Write(summaryTable);
        AnsiConsole.WriteLine();

        // Tier breakdown
        var tierChart = new BarChart()
            .Width(60)
            .Label("[bold]Findings by Tier[/]")
            .CenterLabel()
            .AddItem("CONFIRMED", result.Confirmed.Count, Color.Red)
            .AddItem("HIGH", result.High.Count, Color.Orange1)
            .AddItem("MEDIUM", result.Medium.Count, Color.Yellow)
            .AddItem("LOW", result.Low.Count, Color.Grey);

        AnsiConsole.Write(tierChart);
        AnsiConsole.WriteLine();

        // Detailed findings
        int rank = 0;
        foreach (var finding in result.AllFindings)
        {
            rank++;
            RenderFinding(finding, rank);
        }
    }

    private static void RenderFinding(HijackCandidate c, int rank)
    {
        Color tierColor = c.Tier switch
        {
            ConfidenceTier.Confirmed => Color.Red,
            ConfidenceTier.High => Color.Orange1,
            ConfidenceTier.Medium => Color.Yellow,
            ConfidenceTier.Low => Color.Grey,
            _ => Color.DarkSlateGray1
        };

        string tierLabel = c.Tier.ToString().ToUpper();

        var panel = new Panel(new Rows(
            new Markup($"[bold]Binary:[/]   {Markup.Escape(c.BinaryPath)}"),
            new Markup($"[bold]DLL:[/]      {Markup.Escape(c.DllName)} [dim]({c.Type})[/]"),
            new Markup($"[bold]Path:[/]     {Markup.Escape(c.HijackWritablePath)}"),
            new Markup($"[bold]Trigger:[/]  {c.Trigger} \"{Markup.Escape(c.TriggerIdentifier)}\"" +
                (c.ServiceStartType != null ? $" ({c.ServiceStartType})" : "")),
            new Markup($"[bold]Runs As:[/]  {Markup.Escape(c.RunAsAccount)}"),
            new Markup($"[bold]Proven:[/]   " + (c.CanaryResult == CanaryResult.Fired
                ? $"[green]✓ Canary fired as {Markup.Escape(c.ConfirmedPrivilege ?? "?")}, " +
                  $"{c.ConfirmedIntegrityLevel} integrity[/]"
                : c.CanaryResult == CanaryResult.NotTested
                    ? "[yellow]○ Not tested[/]"
                    : $"[red]✗ {c.CanaryResult}[/]")),
            new Markup($"[bold]Survives Reboot:[/] " +
                (c.SurvivesReboot ? "[green]✓ Yes[/]" : "[dim]No[/]")),
            new Markup($"[bold]Use Cases:[/] " +
                (c.UseCases.Any() ? string.Join(", ", c.UseCases) : "General")),
            c.Notes.Any()
                ? new Markup($"\n[dim]{string.Join("\n", c.Notes.Select(n => "  • " + Markup.Escape(n)))}[/]")
                : new Markup("")
        ))
        {
            Header = new PanelHeader(
                $"#{rank} [[{tierLabel}]] Score: {c.FinalScore:F1} | " +
                $"Confidence: {c.Confidence:F0}% | Impact: {c.ImpactScore:F1}",
                Justify.Left),
            Border = BoxBorder.Rounded,
            BorderStyle = new Style(tierColor)
        };

        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }

    public static async Task GenerateJsonReport(ScanResult result, string outputPath)
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Converters = { new JsonStringEnumConverter() }
        };

        string json = JsonSerializer.Serialize(result, options);
        await File.WriteAllTextAsync(outputPath, json);
        AnsiConsole.MarkupLine($"[green]JSON report saved to: {Markup.Escape(outputPath)}[/]");
    }

    public static async Task GenerateHtmlReport(ScanResult result, string outputPath)
    {
        string html = HtmlReportTemplate.Generate(result);
        await File.WriteAllTextAsync(outputPath, html);
        AnsiConsole.MarkupLine($"[green]HTML report saved to: {Markup.Escape(outputPath)}[/]");
    }
}
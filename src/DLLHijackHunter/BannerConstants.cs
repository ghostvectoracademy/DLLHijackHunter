using Spectre.Console;

namespace DLLHijackHunter;

public static class BannerConstants
{
    private static readonly string[] BannerLines =
    {
        "[cyan1]    ____  __    __    __  ___   _            __   __  __            __           [/]",
        "[cyan1]   / __ \\/ /   / /   / / / (_) (_)___ ______/ /__/ / / /_  ______  / /____  _____[/]",
        "[cyan1]  / / / / /   / /   / /_/ / / / / __ `/ ___/ //_/ /_/ / / / / __ \\/ __/ _ \\/ ___/[/]",
        "[cyan1] / /_/ / /___/ /___/ __  / / / / /_/ / /__/ ,< / __  / /_/ / / / / /_/  __/ /    [/]",
        "[cyan1]/_____/_____/_____/_/ /_/_/_/ /\\__,_/\\___/_/|_/_/ /_/\\__,_/_/ /_/\\__/\\___/_/     [/]",
        "[cyan1]                         /___/                                                    [/]",
        "[bold grey]                              By GhostVector Academy[/]",
    };

    public static void PrintBanner()
    {
        foreach (var line in BannerLines)
            AnsiConsole.MarkupLine(line);

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[dim]Automated DLL Hijacking Detection — Zero False Positives[/]");
    }
}

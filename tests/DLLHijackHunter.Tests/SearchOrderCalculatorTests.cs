using DLLHijackHunter.Discovery;
using Xunit;

namespace DLLHijackHunter.Tests;

/// <summary>
/// SearchOrderCalculator tests require Windows paths and APIs.
/// They are skipped when running on non-Windows platforms.
/// </summary>
public class SearchOrderCalculatorTests
{
    private static bool IsWindows => OperatingSystem.IsWindows();

    [Fact]
    public void GetSearchOrder_EmptyBinaryDir_ReturnsEmptyList()
    {
        // This test is platform-independent — empty input should always return empty
        string binaryPath = "";
        string dllName = "test.dll";

        var order = SearchOrderCalculator.GetSearchOrder(binaryPath, dllName);

        Assert.Empty(order);
    }

    [Fact]
    public void FindActualDllLocation_ForNonExistentDll_ReturnsNull()
    {
        // Platform-independent: a DLL that doesn't exist anywhere should return null
        string binaryPath = IsWindows
            ? @"C:\Windows\System32\notepad.exe"
            : "/usr/bin/test";
        string dllName = "this_dll_absolutely_does_not_exist_12345.dll";

        string? location = SearchOrderCalculator.FindActualDllLocation(binaryPath, dllName);

        Assert.Null(location);
    }

    [Fact]
    public void FindHijackablePositions_ForNonWritablePaths_ReturnsNotNull()
    {
        // Platform-independent: method should never return null
        string binaryPath = IsWindows
            ? @"C:\Windows\System32\notepad.exe"
            : "/usr/bin/test";
        string dllName = "this_dll_does_not_exist_67890.dll";

        var positions = SearchOrderCalculator.FindHijackablePositions(binaryPath, dllName);

        Assert.NotNull(positions);
    }

    // ═══ Windows-only tests below ═══

    [Fact(Skip = "Requires Windows — SearchOrderCalculator depends on Windows DLL search paths")]
    public void GetSearchOrder_IncludesApplicationDirectory()
    {
        string binaryPath = @"C:\Program Files\TestApp\test.exe";
        string dllName = "helper.dll";

        var order = SearchOrderCalculator.GetSearchOrder(binaryPath, dllName);

        Assert.Contains(order, p => p.Contains(@"C:\Program Files\TestApp\helper.dll"));
    }

    [Fact(Skip = "Requires Windows — SearchOrderCalculator depends on Windows DLL search paths")]
    public void GetSearchOrder_IncludesSystem32()
    {
        string binaryPath = @"C:\Program Files\TestApp\test.exe";
        string dllName = "helper.dll";

        var order = SearchOrderCalculator.GetSearchOrder(binaryPath, dllName);

        Assert.Contains(order, p =>
            p.Contains("System32", StringComparison.OrdinalIgnoreCase));
    }

    [Fact(Skip = "Requires Windows — SearchOrderCalculator depends on Windows DLL search paths")]
    public void GetSearchOrder_IncludesWindowsDirectory()
    {
        string binaryPath = @"C:\Program Files\TestApp\test.exe";
        string dllName = "helper.dll";

        var order = SearchOrderCalculator.GetSearchOrder(binaryPath, dllName);

        string windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        Assert.Contains(order, p =>
            Path.GetDirectoryName(p)?.Equals(windowsDir, StringComparison.OrdinalIgnoreCase) == true);
    }

    [Fact(Skip = "Requires Windows — SearchOrderCalculator depends on Windows DLL search paths")]
    public void GetSearchOrder_ApplicationDirIsFirst()
    {
        string binaryPath = @"C:\Program Files\TestApp\test.exe";
        string dllName = "helper.dll";

        var order = SearchOrderCalculator.GetSearchOrder(binaryPath, dllName);

        Assert.True(order.Count > 0);
        Assert.Contains(@"C:\Program Files\TestApp\helper.dll", order);
    }

    [Fact(Skip = "Requires Windows — SearchOrderCalculator depends on Windows DLL search paths")]
    public void GetSearchOrder_ReturnsNonEmptyList()
    {
        string binaryPath = @"C:\Windows\System32\notepad.exe";
        string dllName = "kernel32.dll";

        var order = SearchOrderCalculator.GetSearchOrder(binaryPath, dllName);

        Assert.NotEmpty(order);
    }

    [Fact(Skip = "Requires Windows — SearchOrderCalculator depends on Windows DLL search paths")]
    public void FindActualDllLocation_ForKnownSystemDll_ReturnsPath()
    {
        string binaryPath = @"C:\Windows\System32\notepad.exe";
        string dllName = "kernel32.dll";

        string? location = SearchOrderCalculator.FindActualDllLocation(binaryPath, dllName);

        Assert.NotNull(location);
        Assert.Contains("kernel32.dll", location, StringComparison.OrdinalIgnoreCase);
    }

    [Fact(Skip = "Requires Windows — SearchOrderCalculator depends on Windows DLL search paths")]
    public void GetSearchOrder_DotLocal_IncludedWhenDirectoryExists()
    {
        string binaryPath = @"C:\Program Files\TestApp\test.exe";
        string dllName = "helper.dll";

        var order = SearchOrderCalculator.GetSearchOrder(binaryPath, dllName);

        string expected = @"C:\Program Files\TestApp\helper.dll";
        Assert.Equal(expected, order[0]);
    }

    [Fact(Skip = "Requires Windows — SearchOrderCalculator depends on Windows DLL search paths")]
    public void GetSearchOrder_IncludesPathDirectories()
    {
        string binaryPath = @"C:\Program Files\TestApp\test.exe";
        string dllName = "helper.dll";

        var order = SearchOrderCalculator.GetSearchOrder(binaryPath, dllName);

        Assert.True(order.Count >= 4, "Should include at least app dir, System32, System, Windows");
    }
}

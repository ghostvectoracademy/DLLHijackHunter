namespace DLLHijackHunter.Discovery;

public static class KnowledgeBaseEngine
{
    // Dictionary mapping: BinaryName -> Dictionary<DllName, HijackLibs URL/Reference>
    private static readonly Dictionary<string, Dictionary<string, string>> HijackLibsDatabase = new(StringComparer.OrdinalIgnoreCase)
    {
        { "Teams.exe", new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
            { "dbghelp.dll", "https://hijacklibs.net/entries/microsoft/teams.html" },
            { "wtsapi32.dll", "https://hijacklibs.net/entries/microsoft/teams.html" }
        }},
        { "OneDrive.exe", new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
            { "version.dll", "https://hijacklibs.net/entries/microsoft/onedrive.html" },
            { "wintrust.dll", "https://hijacklibs.net/entries/microsoft/onedrive.html" },
            { "userenv.dll", "https://hijacklibs.net/entries/microsoft/onedrive.html" }
        }},
        { "Discord.exe", new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
            { "dxgi.dll", "https://hijacklibs.net/entries/discord/discord.html" }
        }},
        { "Notepad++.exe", new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
            { "SciLexer.dll", "https://hijacklibs.net/entries/notepadplusplus/notepad++.html" }
        }},
        { "Code.exe", new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { // VS Code
            { "dxgi.dll", "https://hijacklibs.net/entries/microsoft/vscode.html" }
        }},
        { "VBoxService.exe", new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { // VirtualBox
            { "VERSION.dll", "https://hijacklibs.net/entries/oracle/virtualbox.html" }
        }},
        { "chrome.exe", new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
            { "goopdate.dll", "https://hijacklibs.net/entries/google/chrome.html" }
        }},
        { "AcroRd32.exe", new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { // Adobe Reader
            { "icucnv58.dll", "https://hijacklibs.net/entries/adobe/acrobat.html" }
        }},
        { "Spotify.exe", new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
            { "dpapi.dll", "https://hijacklibs.net/entries/spotify/spotify.html" }
        }},
        { "GUP.exe", new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { // Google Update
            { "libcurl.dll", "https://hijacklibs.net/entries/google/gup.html" }
        }}
    };

    /// <summary>
    /// Checks if a binary/dll combo is a documented vulnerability in HijackLibs.
    /// </summary>
    public static bool CheckKnowledgeBase(string binaryPath, string dllName, out string? referenceUrl)
    {
        referenceUrl = null;
        string binaryName = Path.GetFileName(binaryPath);

        if (HijackLibsDatabase.TryGetValue(binaryName, out var vulnerableDlls))
        {
            if (vulnerableDlls.TryGetValue(dllName, out referenceUrl))
            {
                return true;
            }
        }
        return false;
    }
}
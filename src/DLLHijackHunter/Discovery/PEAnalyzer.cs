// src/DLLHijackHunter/Discovery/PEAnalyzer.cs

using PeNet;
using PeNet.Header.Pe;

namespace DLLHijackHunter.Discovery;

public class PEAnalyzer
{
    /// <summary>
    /// Get all DLLs imported by a PE file (standard imports + delay loads).
    /// </summary>
    public static PEAnalysisResult Analyze(string filePath)
    {
        var result = new PEAnalysisResult { FilePath = filePath };

        try
        {
            var pe = new PeFile(filePath);

            // Standard imports
            if (pe.ImportedFunctions != null)
            {
                foreach (var func in pe.ImportedFunctions)
                {
                    if (!string.IsNullOrEmpty(func.DLL))
                        result.ImportedDlls.Add(func.DLL.ToLowerInvariant());
                }
            }

            // Delay-loaded imports
            // PeNet 4.x ImportedFunctions already includes delay-loaded imports above.
            // The raw ImageDelayImportDescriptor only has RVA fields (uint), not resolved names.
            // We identify delay-loaded DLLs by collecting standard import DLL names from
            // ImportedFunctions, then checking which DLLs come from the delay import table.
            try
            {
                if (pe.ImageDelayImportDescriptor != null && pe.ImportedFunctions != null)
                {
                    // Collect DLL names already seen in standard import descriptors
                    var standardDlls = new HashSet<string>(result.ImportedDlls, StringComparer.OrdinalIgnoreCase);

                    // Any imported DLL not in the standard set is likely delay-loaded
                    foreach (var func in pe.ImportedFunctions)
                    {
                        if (!string.IsNullOrEmpty(func.DLL) && !standardDlls.Contains(func.DLL.ToLowerInvariant()))
                            result.DelayLoadDlls.Add(func.DLL.ToLowerInvariant());
                    }
                }
            }
            catch { /* Some PEs have malformed delay imports */ }

            // Check for embedded manifest
            result.HasEmbeddedManifest = CheckForManifest(pe, filePath);

            // Check for LoadLibrary calls (heuristic from import table)
            if (pe.ImportedFunctions != null)
            {
                var funcNames = pe.ImportedFunctions
                    .Where(f => !string.IsNullOrEmpty(f.Name))
                    .Select(f => f.Name!)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

                result.UsesLoadLibrary = funcNames.Any(n =>
                    n.Contains("LoadLibrary", StringComparison.OrdinalIgnoreCase));

                result.UsesLoadLibraryEx = funcNames.Any(n =>
                    n.Contains("LoadLibraryEx", StringComparison.OrdinalIgnoreCase));

                result.CallsSetDllDirectory = funcNames.Any(n =>
                    n.Contains("SetDllDirectory", StringComparison.OrdinalIgnoreCase));

                result.CallsSetDefaultDllDirectories = funcNames.Any(n =>
                    n.Contains("SetDefaultDllDirectories", StringComparison.OrdinalIgnoreCase));

                result.CallsAddDllDirectory = funcNames.Any(n =>
                    n.Contains("AddDllDirectory", StringComparison.OrdinalIgnoreCase));
            }

            // Get exported functions (for DLL proxy generation)
            try
            {
                if (pe.ExportedFunctions != null)
                {
                    result.Exports = pe.ExportedFunctions
                        .Where(e => !string.IsNullOrEmpty(e.Name))
                        .Select(e => e.Name!)
                        .ToList();
                }
            }
            catch { }

            // Is 64-bit?
            result.Is64Bit = pe.Is64Bit;

            // Is signed? - Check if authenticode signature exists
            try
            {
                result.IsSigned = pe.HasValidAuthenticodeSignature;
            }
            catch
            {
                // Fallback: check if signature directory exists
                try
                {
                    result.IsSigned = pe.ImageNtHeaders?.OptionalHeader?.DataDirectory != null &&
                        pe.ImageNtHeaders.OptionalHeader.DataDirectory.Length > 4 &&
                        pe.ImageNtHeaders.OptionalHeader.DataDirectory[4].VirtualAddress != 0;
                }
                catch
                {
                    result.IsSigned = false;
                }
            }

            // Check DllCharacteristics for FORCE_INTEGRITY
            try
            {
                if (pe.ImageNtHeaders?.OptionalHeader != null)
                {
                    var chars = pe.ImageNtHeaders.OptionalHeader.DllCharacteristics;
                    // Cast enum to ushort for bitwise operations
                    result.ForceIntegrity = ((ushort)chars & 0x0080) != 0;
                }
            }
            catch { }
        }
        catch (Exception ex)
        {
            result.AnalysisError = ex.Message;
        }

        return result;
    }

    /// <summary>
    /// Get exports from a DLL file (for proxy DLL generation).
    /// </summary>
    public static List<string> GetExports(string dllPath)
    {
        try
        {
            var pe = new PeFile(dllPath);
            return pe.ExportedFunctions?
                .Where(e => !string.IsNullOrEmpty(e.Name))
                .Select(e => e.Name!)
                .ToList() ?? new List<string>();
        }
        catch
        {
            return new List<string>();
        }
    }

    /// <summary>
    /// Checks for an embedded manifest using multiple methods.
    /// </summary>
    private static bool CheckForManifest(PeFile pe, string filePath)
    {
        // Method 1: Check resource directory for RT_MANIFEST (type 24)
        try
        {
            var resourceDir = pe.ImageResourceDirectory;
            if (resourceDir?.DirectoryEntries != null)
            {
                foreach (var entry in resourceDir.DirectoryEntries)
                {
                    try
                    {
                        // PeNet 4.x uses NameResolved property
                        if (entry.NameResolved != null && 
                            entry.NameResolved.Equals("RT_MANIFEST", StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                        
                        // Also check numeric ID (24 = RT_MANIFEST)
                        // In PeNet 4.x, Name can be numeric string
                        if (entry.IsIdEntry && entry.ID == 24)
                        {
                            return true;
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        // Method 2: Search raw bytes for manifest XML signature
        try
        {
            byte[] rawBytes;
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                // Read at most 2MB to search for manifest
                int readSize = (int)Math.Min(fs.Length, 2 * 1024 * 1024);
                rawBytes = new byte[readSize];
                fs.Read(rawBytes, 0, readSize);
            }

            string content = System.Text.Encoding.UTF8.GetString(rawBytes);
            if (content.Contains("assembly xmlns", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("assemblyIdentity", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("trustInfo xmlns", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        catch { }

        // Method 3: Check for external manifest file
        string externalManifest = filePath + ".manifest";
        if (File.Exists(externalManifest))
            return true;

        return false;
    }
}

public class PEAnalysisResult
{
    public string FilePath { get; set; } = "";
    public HashSet<string> ImportedDlls { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> DelayLoadDlls { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public bool HasEmbeddedManifest { get; set; }
    public string? ManifestContent { get; set; }
    public bool UsesLoadLibrary { get; set; }
    public bool UsesLoadLibraryEx { get; set; }
    public bool CallsSetDllDirectory { get; set; }
    public bool CallsSetDefaultDllDirectories { get; set; }
    public bool CallsAddDllDirectory { get; set; }
    public List<string> Exports { get; set; } = new();
    public bool Is64Bit { get; set; }
    public bool IsSigned { get; set; }
    public bool ForceIntegrity { get; set; }
    public string? AnalysisError { get; set; }

    public HashSet<string> AllImportedDlls =>
        new(ImportedDlls.Concat(DelayLoadDlls), StringComparer.OrdinalIgnoreCase);
}
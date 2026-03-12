using System;
using System.Reflection;
using PeNet;

class Program {
    static void Main() {
        Console.WriteLine("PeFile properties:");
        var pe = new PeFile("/home/ghosty/DLLHijackingHunter/src/DLLHijackHunter/bin/Debug/net8.0-windows/win-x64/DLLHijackHunter.exe");
        Console.WriteLine("\nImportedFunctions:");
        var dict = new System.Collections.Generic.Dictionary<string, int>();
        foreach (var func in pe.ImportedFunctions) {
            if (func.DLL != null) {
                if (!dict.ContainsKey(func.DLL)) dict[func.DLL] = 0;
                dict[func.DLL]++;
            }
        }
        foreach (var kvp in dict) Console.WriteLine($"{kvp.Key}: {kvp.Value}");
        Console.WriteLine("\nHas ImageDelayImportDescriptor: " + (pe.ImageDelayImportDescriptor != null));
    }
}

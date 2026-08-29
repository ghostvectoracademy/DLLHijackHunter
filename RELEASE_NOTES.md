## v2.4.0 — Verification & Analysis Fixes

Seven bug fixes targeting false positives, analysis accuracy, and operational correctness. No breaking changes.

### Bug Fixes

**ReportGenerator — console crash on redirected stdout**
`AnsiConsole.Clear()` threw `IOException: The handle is invalid` whenever `--output` was used or stdout was piped. Guarded with `!Console.IsOutputRedirected`.

**CanaryDllBuilder — loadprobe.dll leaked after scan**
`CleanupAll()` removed MSVC build artifacts but never deleted `%ProgramData%\DLLHijackHunter\loadprobe.dll`. The file now accumulates across scans until an explicit cleanup. Fixed — probe DLL is deleted in `CleanupAll()`.

**LoadLibraryExFlagsFilter — AnalysisConfidence mislabeled**
All five confidence assignment sites were using incorrect labels, producing misleading filter output:
- `SetDefaultDllDirectories` / `AddDllDirectory` detections → `Certain` (was `IndirectCall`)
- `LoadLibraryEx` with runtime-unknown flags → `Unknown` (was `IndirectCall`)
- Plain `LoadLibrary` (standard search order confirmed) → `CertainDirect` (was `Certain`)
- Import-table-only loads (no LoadLibrary call) → `CertainDirect` (was `Certain`)

**KnowledgeBaseEngine — false KB hits on generic binary names**
Matching solely on binary basename caused `setup.exe`, `update.exe`, `installer.exe`, and similar high-collision names to spuriously set `IsKnownVulnerability = true`, bypassing the 79% static-only confidence cap. Matches for these names now require at least one parent-directory path hint from the HijackLibs dataset to appear in the binary's actual path.

**LoadProbe — wrong search model for service candidates**
All candidates were verified with `LOAD_LIBRARY_SEARCH_USER_DIRS | SEARCH_SYSTEM32 | ...` (opt-in modern ordering). Service binaries use the traditional unmodified search order (`SetCurrentDirectory` + `LoadLibraryW`). Service candidates are now probed with the correct model, eliminating both false wins and false losses for that trigger type.

**StartupItemEnumerator — SilentProcessExit (T1546.012) not enumerated**
`IFEO\<image>\SilentProcessExit\MonitorProcess` entries were not discovered at all. When a monitored image exits, Windows launches `MonitorProcess` — typically under the user or service account that triggered the exit. These are now surfaced as hijack candidates.

**AutoElevateEnumerator — fragile manifest detection**
`IsAutoElevate()` read up to 2 MB of each EXE as raw UTF-8 and searched for `<autoElevate>true</autoElevate>`, missing binaries with embedded `RT_MANIFEST` resources, whitespace variants in the XML, or external `.manifest` sidecar files. Replaced with `PEAnalyzer.Analyze()`, which already handles all three cases.

---

**Full changelog:** https://github.com/ghostvectoracademy/DLLHijackHunter/commits/main

Presented at **Black Hat Arsenal @ SecTor 2026** · [projectmerai.com](https://projectmerai.com)

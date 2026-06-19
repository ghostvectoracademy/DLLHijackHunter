# DLLHijackHunter — Independent Code Analysis

*Analyst: Claude (Fable). Scope: complete read of all 40 `.cs` source files + embedded resources, plus an actual `dotnet build` and a `--profile safe` run on the host. Every claim is cited `file:line`. Conclusions are my own; I did not consult any prior analysis.*

Version analyzed: 2.1.0 · TargetFrameworks `net8.0-windows;net10.0-windows` (`DLLHijackHunter.csproj:6`).

---

## 0. Verdict up front

DLLHijackHunter is a **competent discovery-and-triage scanner wrapped in claims it does not deliver**. The enumeration breadth (services, svchost ServiceDlls, tasks, run keys, startup folders, COM, AutoElevate manifests, COM elevation, PATH weaponization, ETW) is real and mostly works. The PE import/delay-import parsing is real. The filter pipeline is a sensible idea and partly implemented.

But the three features the README sells as its differentiators are each broken or hollow in practice:

1. **"ACL-based writability check" is privilege-relative and silently inverts when run elevated** — which the README *recommends*. Run as admin (required for canary/ETW), every `System32` / `Program Files` / `Windows` directory is judged writable, so the headline false-positive gate passes nearly everything. (`Native/AclChecker.cs:79-104`)
2. **"Canary confirmation" requires `cl.exe` (MSVC) present on the target** and silently degrades to "Not tested" without it (`Canary/CanaryDllBuilder.cs:198`), and **its architecture handling is a no-op** — the detected bitness is computed and then never used to select a toolchain (`Canary/CanaryDllBuilder.cs:193-205`).
3. **"Threat intel correlation (HijackLibs-style)" is 10 hardcoded binaries / ~16 DLL mappings** (`Discovery/KnowledgeBaseEngine.cs:6-41`), versus HijackLibs' ~400+ entries.

The banner literally prints **"Zero False Positives"** (`BannerConstants.cs:24`). Given how writability is judged, that is the opposite of true.

Four of the ten advertised hijack types (`CWD`, `KnownDllBypass`, `IFEO`, `AppCertDll`) are **enum values that are never produced** by any discovery path.

---

## PASS 1 — Complete understanding

### 1. File-by-file map

**Entry / orchestration**
- `Program.cs` — CLI (System.CommandLine), profile build, 4-phase orchestration, output dispatch. Depends on every subsystem. Nothing depends on it.
- `BannerConstants.cs` — ASCII banner; prints the "Zero False Positives" tagline (`:24`). Used by `Program` and `ReportGenerator`.
- `ScanLogger.cs` — static logger to console + optional file. Used throughout discovery/filter/canary.

**Models** (`Models/`)
- `HijackCandidate.cs` — the central record (see §3). Read/written everywhere.
- `ScanProfile.cs` — 5 named profiles + `FromName`. Consumed by every engine.
- `ScanResult.cs` — output aggregate; tiered lists + `AllFindings` + `AttackChains`.
- `DiscoveryContext.cs` — unified static/ETW execution-context record produced by enumerators, consumed by `StaticDiscoveryEngine`/`ETWDiscoveryEngine`.
- `AttackChain.cs` — chain/step DTOs produced by `AttackChainCorrelator`, rendered by `ReportGenerator`.

**Native** (`Native/`)
- `NativeMethods.cs` — P/Invoke surface (kernel32/advapi32/ntdll/wintrust). Several declared imports are **never called** (see §4).
- `AclChecker.cs` — managed ACL writability via `DirectoryInfo.GetAccessControl`. The single most load-bearing — and most flawed — helper. Used by every discovery vector and the writability filter.
- `TokenHelper.cs` — integrity level / token user / elevation via Win32. Used by ETW, privilege filter, startup enumerator.

**Discovery** (`Discovery/`)
- `StaticDiscoveryEngine.cs` — the spine of Phase 1: enumerate contexts → PE-analyze each binary → emit candidates (search-order, phantom, .local, sideload, AppInit, PATH). Depends on all enumerators + `PEAnalyzer` + `SearchOrderCalculator` + `AclChecker` + `KnowledgeBaseEngine`.
- `ServiceEnumerator.cs` — registry `Services` walk + svchost ServiceDll resolution.
- `ScheduledTaskEnumerator.cs` — TaskScheduler library walk.
- `StartupItemEnumerator.cs` — Run/RunOnce keys (HKLM+HKCU+Wow64), Startup folders, AppInit_DLLs, IFEO.
- `COMEnumerator.cs` — `HKCR\CLSID` Inproc/LocalServer32, incl. phantom COM.
- `AutoElevateEnumerator.cs` — System32/SysWOW64 manifest `autoElevate` scan (parallel) + COM `Elevation\Enabled=1`.
- `ETWDiscoveryEngine.cs` — kernel ETW session; image-load + failed-file-open heuristics; triggers services/tasks to provoke loads.
- `PEAnalyzer.cs` — PeNet-based imports, manual delay-import directory parse, manifest detection (3 methods), LoadLibrary/SetDllDirectory import heuristics, exports, signature, FORCE_INTEGRITY.
- `SearchOrderCalculator.cs` — builds the DLL search order honoring `SafeDllSearchMode`; finds writable positions before the real DLL.
- `KnowledgeBaseEngine.cs` — the 10-entry hardcoded "HijackLibs" map.
- `SvchostResolver.cs` — ServiceDll lookup from registry.
- `CommandLineParser.cs` — best-effort ImagePath/command-line → exe path, with cmd/powershell/rundll32 unwrapping.

**Filters** (`Filters/`)
- `IFilter.cs` — `IHardGate` (removes) / `ISoftGate` (penalizes) interfaces.
- `FilterPipeline.cs` — runs 3 hard gates then 5 soft gates, dedups, optional same-priv filter.
- Hard gates: `ApiSetSchemaFilter`, `KnownDllsFilter`, `WritabilityFilter`.
- Soft gates: `WinSxSManifestFilter`, `PrivilegeDeltaFilter`, `LoadLibraryExFlagsFilter`, `SignatureVerificationFilter`, `ErrorHandledLoadFilter`.

**Canary** (`Canary/`)
- `CanaryEngine.cs` — per-candidate orchestration: build → backup → deploy → trigger → poll confirm file → cleanup/restore.
- `CanaryDllBuilder.cs` — generates C source, compiles with `cl.exe`, optional export-forward proxy.
- `TriggerExecutor.cs` — `sc.exe` / `schtasks.exe` / PowerShell COM activation.

**Scoring** (`Scoring/`)
- `TieredScorer.cs` — confidence adjustments, tiering, impact, final weighted score.
- `AttackChainCorrelator.cs` — builds "Direct Path / Ladder / Long Con" narrative chains.

**Reporting** (`Reporting/`)
- `ReportGenerator.cs` — console (Spectre), JSON, HTML dispatch + attack-chain tree.
- `HtmlReportTemplate.cs` — static dark-theme HTML.

### 2. One scan, end-to-end (with field provenance)

`Program.Main` → `RunScan` (`Program.cs:136`):

1. **Profile build** (`Program.cs:172-185`). `ScanProfile.FromName` returns a named profile, then `profile.MinConfidence = minConfidence` (`:173`) **unconditionally overwrites** the profile's own threshold with the CLI value (default 20). See §"Broken" — this kills the documented per-profile thresholds.

2. **Discovery** (`StaticDiscoveryEngine.Discover`, `:55`):
   - Enumerators return `List<DiscoveryContext>`; each sets `BinaryPath`, `TriggerType`, `TriggerIdentifier`, `DisplayName`, `RunAsAccount`, `StartType`, `IsAutoStart`, `RepeatInterval`, `IsSvchostService`.
   - For each unique existing binary, `PEAnalyzer.Analyze` yields `AllImportedDlls` (`PEAnalyzer.cs:308`).
   - `AnalyzeDllImport` (`:236`) sets on each `HijackCandidate`: `BinaryPath`, `DllName`, `DllLegitPath` (from `SearchOrderCalculator.FindActualDllLocation`), `Type` (Phantom if no legit path else SearchOrder), `HijackWritablePath`, `Trigger`/`TriggerIdentifier`/`RunAsAccount`/`ServiceStartType`/`TaskFrequency`/`SurvivesReboot` (from the highest-priority context, `:248`), `IsKnownVulnerability`/`KnowledgeBaseReference` (`:242`), `Notes`.
   - `.local`, AutoElevate sideload, phantom-DB, AppInit, and PATH-weaponization candidates are emitted by sibling methods (`:276`, `:310`, `:354`, `:152`, `:386`).

3. **ETW merge** (`Program.cs:211-238`) only if `RunETW && isElevated`. ETW candidates set `BinaryPath`/`DllName`/`DllLegitPath`/`Type`/`HijackWritablePath`/`RunAsAccount`/`DiscoverySource="etw"`/`Notes`; `EnrichWithStaticData` (`ETWDiscoveryEngine.cs:106`) back-fills `RunAsAccount`/`Trigger`/`ServiceStartType`/`SurvivesReboot`.

4. **Filter pipeline** (`FilterPipeline.Process`, `:33`): hard gates write `FilterResults["ApiSetSchema"|"KnownDLLs"|"Writability"]` and drop on fail. Then each survivor's `Confidence` is reset to `100.0` (`:68`) and soft gates subtract penalties, appending `Notes` and possibly `UseCases`/`PrivDelta`/`LoadLibAnalysisConfidence`/`IsProtectedProcess`/`ManifestCoversThisSpecificDll`. Dedup by `BinaryPath|DllName|HijackWritablePath` (`:131`).

5. **Canary** (`Program.cs:301`) only if `RunCanary && isElevated`. `CanaryEngine.ConfirmAsync` sets `CanaryResult`; on fire, `Confidence=100`, `ConfirmedPrivilege`/`ConfirmedIntegrityLevel`/`ConfirmedSeDebug` from the confirm file (`CanaryEngine.cs:361-364`). Non-elevated path sets everything to `NotTested` (`Program.cs:311-315`).

6. **Scoring** (`TieredScorer.ScoreAll`, `:7`): canary/KB confidence nudges, `Tier`, `ImpactScore` (`CalculateImpact`), `FinalScore = (Conf/100*0.4 + Impact/10*0.6)*10` (`:57`), UseCases.

7. **Min-confidence + confirmed-only filter, ordering** (`Program.cs:327-337`), **attack-chain build** (`:340`,`:356`), **output** (`GenerateOutput`, `:373`).

### 3. Data-model audit (set/read)

**Dead — declared but never set (and mostly never read):**
- `BinarySHA256` (`HijackCandidate.cs:70`) — never assigned, never read. The model advertises a hash that is never computed.
- `HasWinVerifyTrust` (`:93`) — never assigned, never read. (`WinVerifyTrust` P/Invoke is also never called — §4.)
- `ProxyExports` (`:116`) — never populated; proxying writes `#pragma` lines into C source instead, so this list is always empty in the report.

**Set but never read (write-only state, leaks only into JSON):**
- `IsProtectedProcess` — set in `SignatureVerificationFilter.cs:37,47,60`; never consumed by scoring or reporting.
- `ManifestCoversThisSpecificDll` — set in `WinSxSManifestFilter` (4 sites); never read.
- `AppStillFunctional` — set `true` in `CanaryEngine.cs:239`; never read (the README's "app still functional" claim is cosmetic).
- `DiscoveredAt`, `Id` — set at construction; never surfaced in any report.
- `profile.OutputFormat` — set in `Program.cs:180` but `GenerateOutput` uses the CLI `format` variable, not the profile field.
- `profile.IncludePPL`, `profile.UseCaseFilter` — set across profiles, never read anywhere.

**Read but never set (type can never occur):**
- `HijackType.CWD` — read in scoring (`TieredScorer.cs:112`), correlator (`AttackChainCorrelator.cs:26`), and `LoadLibraryExFlagsFilter.cs:62`, but **no discovery path ever assigns it**. The CWD-specific `SetDllDirectory` logic in `LoadLibraryExFlagsFilter` is therefore unreachable.
- `HijackType.IFEO`, `HijackType.AppCertDll`, `HijackType.KnownDllBypass` — never assigned anywhere (grep-verified). Enum-only.
- `TriggerType.WMI` — appears only in priority switches; never assigned.

**Live and correct:** `BinaryPath`, `DllName`, `DllLegitPath`, `Type`(Phantom/SearchOrder/SideLoad/DotLocal/EnvPath/AppInitDll), `HijackWritablePath`, `Trigger`, `TriggerIdentifier`, `RunAsAccount`, `ServiceStartType`, `TaskFrequency`, `SurvivesReboot`, `FilterResults`, `Confidence`, `Tier`, `ImpactScore`, `FinalScore`, `IsKnownVulnerability`, `KnowledgeBaseReference`, `UseCases`, `Notes`, `CanaryResult`, `Confirmed*`, `IsSimulatedCopyAttack`, `LoadLibAnalysisConfidence`, `DiscoverySource`.

### 4. External surface

**P/Invoke (`NativeMethods.cs`):** kernel32 (`LoadLibraryExW`, `GetModuleFileNameW`, `QueryFullProcessImageNameW`, `QueryDosDeviceW`, `CloseHandle`, `GetCurrentProcess`), advapi32 (`OpenProcessToken`, `GetTokenInformation`, `LookupAccountSidW`, `GetSid*`, `GetNamedSecurityInfoW`, `GetEffectiveRightsFromAclW`, `BuildTrusteeWithSidW`, `LookupPrivilegeValueW`, `PrivilegeCheck`), ntdll (`NtQueryInformationProcess`, `NtQueryObject`), wintrust (`WinVerifyTrust`).
  - **Actually called:** only the token-info trio used by `TokenHelper` (`OpenProcessToken`, `GetTokenInformation`, `LookupAccountSidW`, `GetSidSubAuthority[Count]`, `GetCurrentProcess`, `CloseHandle`).
  - **Declared but never called:** `LoadLibraryExW`/`FreeLibrary`/`GetModuleFileNameW` (no dynamic load test is performed — writability is the only gate), `QueryFullProcessImageNameW`, `QueryDosDeviceW`, `NtQueryInformationProcess`, `NtQueryObject`, `GetNamedSecurityInfoW`/`GetEffectiveRightsFromAclW`/`BuildTrusteeWithSidW` (the "proper" Win32 ACL path is declared but unused — ACL checks go through managed `DirectoryInfo.GetAccessControl` instead), `LookupPrivilegeValueW`, `PrivilegeCheck`, `WinVerifyTrust`. **The `wintrust`/effective-rights API surface is dead weight.**

**Registry (read-only, HKLM/HKCU/HKCR):** `Services` + `…\Parameters\ServiceDll` + svchost groups; `…\CurrentVersion\Run|RunOnce` (+Wow64); `…\Windows NT\CurrentVersion\Windows` (AppInit); `…\Image File Execution Options`; `HKCR\CLSID`; `HKLM\SOFTWARE\Classes\CLSID\*\Elevation`; `Session Manager\KnownDLLs[32]`, `SafeDllSearchMode`, `ApiSetSchemaExtensions` (opened but **never used** — `ApiSetSchemaFilter.cs:74-78`). All reads; no admin needed for these; failures swallowed.

**ETW:** real-time kernel session `DLLHijackHunter-Trace`, keywords Process/ImageLoad/FileIOInit/FileIO (`ETWDiscoveryEngine.cs:47`). **Requires elevation** (guarded `:26`); on non-admin it returns empty.

**Shell-outs:**
- `sc.exe start/stop/query` (ETW trigger + canary) — needs admin; failures → `false`/swallowed.
- `schtasks.exe /run` — admin for SYSTEM tasks; swallowed.
- `powershell.exe` COM activation (`TriggerExecutor.cs:84`) — exit-code only.
- `where cl.exe` then `cl.exe /LD …` (`CanaryDllBuilder.cs:198,204`) — needs Visual Studio toolchain on the box.
- `WScript.Shell` COM (late-bound) to resolve `.lnk` (`StartupItemEnumerator.cs:100`).

**NuGet:** `Microsoft.Diagnostics.Tracing.TraceEvent` 3.1.8 (ETW), `PeNet` 4.0.1 (PE parse), `System.CommandLine` 2.0.0-beta4 (pre-release), `Spectre.Console` 0.49.1 (UI), `TaskScheduler` 2.12.0 (tasks). (`DLLHijackHunter.csproj:19-25`).

### 5. Capability matrix (implemented / partial / stubbed)

**Hijack types (README's 10):**
| Type | Status | Evidence |
|---|---|---|
| Phantom | **Implemented** | import-DB + search-order + ETW failed-open (`StaticDiscoveryEngine.cs:354`, `ETWDiscoveryEngine.cs:233`) |
| Search Order | **Implemented** | `SearchOrderCalculator.FindHijackablePositions` (`:81`) |
| Side-Loading | **Partial** | only emitted for AutoElevate copy-to-temp (`StaticDiscoveryEngine.cs:310`); no general app-dir sideload type |
| .local Redirect | **Implemented** | `StaticDiscoveryEngine.cs:276` |
| KnownDLL Bypass | **Stubbed** | `HijackType.KnownDllBypass` never assigned; `.local` note only |
| ENV PATH | **Partial** | hardcoded 5-DLL/5-service map (`StaticDiscoveryEngine.cs:406`), not general |
| CWD | **Stubbed** | `HijackType.CWD` never assigned |
| AppInit DLLs | **Partial** | enumerated + candidate, but no `RequireSignedAppInit_DLLs` / Secure-Boot check (`StartupItemEnumerator.cs:130`) |
| IFEO | **Stubbed** | enumerates existing Debuggers as *contexts*; never a hijack candidate; `HijackType.IFEO` unused |
| AppCert DLLs | **Stubbed** | no enumerator, enum unused |

**Discovery vectors:** Services ✅, svchost ServiceDll ✅, Scheduled Tasks ✅, Run/RunOnce ✅, Startup folders ✅ (+`.lnk` resolve), COM ✅, AutoElevate manifest ✅(heuristic), COM elevation ✅, PATH ⚠️(hardcoded), ETW ✅(elevated). WMI ❌.

**Filter gates:** ApiSet ✅, KnownDLLs ✅, Writability ⚠️(privilege-relative — see Pass 2), WinSxS ⚠️(string-match heuristic), PrivDelta ✅, LoadLibraryEx flags ⚠️(import-presence heuristic, cannot read flags), Signature/PPL ⚠️(hardcoded name list), ErrorHandled ⚠️(mostly inert).

**Trigger types that can actually be confirmed:** Service ✅, ScheduledTask ✅, COM ✅(if `TriggerCOM`). Startup/RunKey/Manual/UACBypass → explicitly skipped as "NotTested" (`CanaryEngine.cs:45-53`). So AutoElevate/UAC findings — the entire `uac-bypass` profile — are **never canary-confirmed**, by design.

---

## PASS 2 — Evaluation

### A. README/abstract claims vs. implementation

1. **"Zero False Positives" (banner `:24`) / "False positive reduction ✅".** Contradicted by the writability design (below). When run elevated — the recommended mode — the writability hard gate passes admin-only paths, so the tool emits SYSTEM-writable "findings" that a standard-user attacker could never exploit. This is the single biggest claim/reality gap.

2. **"ACL-based writability check… does NOT fall for UAC virtualization" (`AclChecker.cs:8-10`).** True about virtualization, but it checks **the running process's token**, and `RuleAppliesToIdentity` treats every group in the current token as in-scope plus hardcodes Everyone/AuthUsers/Users (`AclChecker.cs:90-103`). Running elevated, the token carries `BUILTIN\Administrators`, which holds Write/FullControl on `System32`/`Program Files`/`Windows` → those directories report **writable**. The tool measures "can *I* (possibly admin) write," not "can a *low-priv attacker* write." For an LPE tool that inversion is fatal. Only `--lpe-only` (off by default) papers over it with a textual path blocklist (`WritabilityFilter.cs:45-56`).

3. **"Canary confirmation… Built with MSVC (cl.exe)".** Honestly labeled in the build step, but the README's framing ("Instead of guessing, …proves hijacks work") omits that **`cl.exe` is absent on virtually every non-developer target**. Without it, `BuildCanary` returns empty and every candidate becomes `NotTested` (`CanaryDllBuilder.cs:198`, `CanaryEngine.cs:114-119`). The differentiator is unavailable in the field.

4. **"Threat intel correlation" / "HijackLibs-style matches".** It's a 10-app dictionary (`KnowledgeBaseEngine.cs`). Real HijackLibs is ~400+ entries with YAML metadata. Marketing-grade overstatement.

5. **"Proxy DLL generation ✅".** Implemented as name-only `#pragma` export forwarding (`CanaryDllBuilder.cs:184`), self-described as experimental/brittle; ordinals and decorated names break it. Fine as labeled, but the comparison table's bare ✅ oversells it.

6. **"Reboot persistence check ✅".** It's a boolean copied from `IsAutoStart` (`SurvivesReboot`), not a verified persistence test.

7. **Scan-profile table (strict=80%, safe=50% min-confidence).** Dead: `Program.cs:173` overwrites with the CLI default (20) on every run unless the user passes `--min-confidence`. My `safe` run printed **"Min Confidence: 20%"** despite the profile specifying 50 — confirmed empirically (see §F).

8. **Comparison table "Auto trigger (svc/task/COM) ✅".** True for those three, but COM is off except aggressive/redteam, and UAC findings are never triggered.

### B. Broken / fragile / silently failing

- **Writability is privilege-relative (core).** `AclChecker.cs:79-104`. Discussed above. Also note `SearchOrderCalculator.FindHijackablePositions` and every phantom/.local/AppInit path call the same helper, so the flaw is system-wide, not local to the filter.
- **Canary architecture handling is a no-op.** `is64Bit` is detected (`CanaryEngine.cs:89-94`) and threaded into `BuildCanary`→`CompileCanary(…, bool is64Bit, …)`, but `CompileCanary`'s body never references `is64Bit` (or `originalDllPath`) — the `cl.exe` invocation has no `/arch`/platform selection (`CanaryDllBuilder.cs:193-205`). If the developer command prompt is x86 and the victim is x64 (or vice-versa), the canary is the wrong bitness and silently won't load → false `Timeout`/`Failed`. The README's "experimental proxy" caveat does not cover this; it affects *all* canaries, proxy or not.
- **Min-confidence override** (`Program.cs:173`) — §A.7.
- **`ApiSetSchemaExtensions` registry key opened then ignored** (`ApiSetSchemaFilter.cs:74-78`) — dead code; the filter relies on prefix matching + System32 file enumeration (which is adequate, but the registry read is theater).
- **WinSxS soft gate is string matching** over a 2 MB UTF-8 view of the binary (`PEAnalyzer.cs:242-276`); `assemblyBound=true` fallback for any SxS-listed DLL with a manifest (`WinSxSManifestFilter.cs:63`) over-penalizes legitimately hijackable cases and under-penalizes others. Best-effort, as the code admits.
- **Signature/PPL gate is a hardcoded name list** (`SignatureVerificationFilter.cs:16-21,75-81`); misses third-party PPL/AV and any PPL svchost service not in the 6-name set. Conversely it penalizes `svchost.exe`-named entries broadly.
- **LoadLibraryEx gate cannot read flags** — only import-table presence (`LoadLibraryExFlagsFilter.cs`); the author documents this, but it means `SetDefaultDllDirectories` presence (common, benign) applies a 20% penalty to many sound candidates.
- **ErrorHandledLoad gate is nearly inert** — only fires on dynamic-load candidates, which are rarely produced; returns 0 otherwise (`ErrorHandledLoadFilter.cs`).
- **ETW load-order is unprovable** — the engine itself notes "ETW cannot guarantee load priority" (`ETWDiscoveryEngine.cs:224`). Its candidates are heuristics that still flow into scoring as 100%-minus-penalties.
- **Trigger side effects.** `TriggerExecutor.TriggerService` does `sc stop` then `sc start` on live services (`:46-50`); ETW `TriggerServices` starts up to 100 auto-start services and 30 tasks (`ETWDiscoveryEngine.cs:291,326`). On a production box this is disruptive despite "safe research" framing. Canary restore is best-effort and can leave a service stopped or a `.bak` behind if files are locked (`CanaryEngine.cs:283-287`).
- **`IFEO` enumeration semantics are wrong for a hijack tool** — it treats an *existing* Debugger value as a binary to analyze, not as an attacker-writable IFEO key to flag.
- **Exception-swallowing is pervasive** (`catch { }` / `catch { continue; }` in nearly every enumerator and filter). Robust against crashes, but it means partial/empty enumeration is indistinguishable from "clean system" — the tool can silently under-report and still claim a hardened host (`Program.cs:259-260`).
- **`CommandLineParser` progressive path probing** does repeated `File.Exists` over space-split argument permutations (`:138-149`) — correctness-fragile and I/O-heavy on pathological ImagePaths.

### C. Missing vs. state of the art

- No actual **dynamic load probe** (`LoadLibraryEx` with `LOAD_WITH_ALTERED_SEARCH_PATH`) to verify search order — declared P/Invokes go unused.
- No **manifest XML parse** (probedDllPath / `<file name>`); only substring matching.
- No real **HijackLibs/LOLBAS ingestion**; no online or bundled full dataset.
- No **App-dir general sideload** type, no **WinSxS actual resolution**, no **SxS `.manifest` probing path**, no **`KnownDLLs` `.local` real test**, no **AppCertDLLs / Winsock LSP / COM TreatAs / NLS / codecs** vectors.
- Writability not evaluated **from a hypothetical standard-user token** (the correct model for LPE): no impersonation, no "effective rights for `S-1-5-32-545`" computation despite `GetEffectiveRightsFromAclW` being declared.
- No de-noising against **per-user vs machine** scope, no allow-listing of Microsoft-signed legit load directories.

### D. Redesign (not patch)

1. **Writability must be attacker-relative, not process-relative.** Compute effective rights for a chosen low-privilege principal (e.g., `Users` / `Authenticated Users`, or an explicit `--as-sid`) using `GetNamedSecurityInfo` + `GetEffectiveRightsFromAcl` (already declared!) or a Trustee built from that SID — independent of the tool's own token. This makes elevated runs meaningful and is the prerequisite for the "Zero FP" claim.
2. **Confirmation must not depend on a compiler.** Ship a precompiled, signed, dual-arch canary pair (x86+x64) as embedded resources and pick by victim bitness; drop the `cl.exe` dependency entirely. Then architecture handling becomes real.
3. **Replace the 10-entry KB with a bundled HijackLibs snapshot** (YAML/JSON) refreshed at build time.
4. **Collapse the dead enum/type surface** (CWD/IFEO/AppCert/KnownDllBypass/WMI, BinarySHA256, HasWinVerifyTrust, ProxyExports) — either implement or remove; right now they inflate the capability table.
5. **Separate "discovered" from "verified" confidence** so static heuristics can't reach 100%/High without a probe; reserve High/Confirmed for an actual load or effective-rights proof.

### E. Top fixes, priority order

1. **Make `AclChecker` attacker-relative** (or at minimum force `--lpe-only`-style filtering on by default and check `Users`/`Authenticated Users` effective rights, never the elevated token's groups). *Highest impact on FP rate.* (`Native/AclChecker.cs:79-104`)
2. **Stop clobbering profile `MinConfidence`** — only override when the user explicitly passes `--min-confidence`. (`Program.cs:173`)
3. **Fix/raise canary arch handling** and ship a precompiled canary so Phase 3 works without VS. (`Canary/CanaryDllBuilder.cs:193-205`,`:198`)
4. **Re-tune or gate static confidence** so unverified candidates can't land in High; drop the "Zero False Positives" banner. (`Scoring/TieredScorer.cs`, `BannerConstants.cs:24`)
5. **Remove dead model/P-Invoke/enum surface or implement it**; correct the README capability/comparison tables. (`HijackCandidate.cs`, `NativeMethods.cs`, README)
6. **Make `IFEO`/`AppCert` real or delete them from the README's hijack-type table.**

### F. Realistic false-positive rate

- **Run elevated (recommended mode), default profile:** very high. Because the writability gate passes admin-writable system directories, the dominant output is "SYSTEM/admin binary imports DLL X and `System32` is 'writable'" — not exploitable by an unprivileged attacker. I'd estimate the **majority of High/Medium findings are non-actionable** in this mode (order-of-magnitude: well over half; for pure search-order candidates against System32/Program Files, effectively all).
- **Run as standard user:** much better — the ACL check then reflects a real low-priv token, so survivors are genuinely user-writable. But standard-user runs disable ETW and canary, so you get unverified static heuristics, and load-order/manifest/LoadLibraryEx uncertainty still yields a meaningful minority of false positives (manifest-bound, SetDefaultDllDirectories, SxS-managed DLLs that won't actually be hijacked).
- **`--lpe-only` as standard user:** the most trustworthy configuration; FP rate drops to "normal scanner" territory, dominated by the heuristic soft-gate uncertainty rather than the writability inversion.

Net: the banner's "Zero False Positives" is the inverse of the tool's actual default behavior. The tool is most useful as a **standard-user, `--lpe-only`, no-canary triage scanner**, which is almost the opposite of the README's recommended "elevated, aggressive, canary" workflow.

---

## Empirical run (proof, not reading)

- **Build:** `dotnet build -c Release -f net8.0-windows` → **succeeded**, 1 nullable warning (`PEAnalyzer.cs:222`). 0 errors.
- **`--profile safe --format json` (run elevated, "Elevated: Yes"):** completed in **36 min 34 s** on this host. The pipeline counters (from the tool's own output) are the proof of every Pass-2 claim:

| Stage | Count | Note |
|---|---|---|
| Candidates discovered | **415,740** | combinatorial blow-up: every imported DLL × every "writable" search-order dir |
| After API Set gate | 5,811 | removed **409,929 (99%)** — almost all generated candidates were `api-ms-*`/`ext-ms-*` |
| After KnownDLLs gate | 5,474 | removed 337 (6%) |
| After **Writability (ACL) gate** | **5,474** | **removed 0 (0%)** |
| After dedup | 5,179 | |
| **Findings reported** | **5,174** | **0 confirmed · 4,039 HIGH · 909 medium · 226 low** |

  - **The headline FP-killer eliminated nothing.** In the serialized JSON, `"Writability": "Passed"` appears **10,350 times and `"Failed": 0 times`** — because the elevated token can write everywhere. This is the privilege-relative flaw, measured.
  - **4,039 findings landed in the HIGH tier (≥80% confidence) with 0 verified** (canary is off in `safe`). That is the false-positive surface in one number.
  - **6,189** `HijackWritablePath` values sit inside `…\System32\…` and **2,717** inside `Program Files` — all marked exploitable.
  - **Representative false positive:** `"HijackWritablePath": "C:\WINDOWS\System32\APHostService.dll.local\ntdll.dll"` — flagged as a `.local` hijack even though (a) creating a `.local` directory *inside `System32`* requires admin, and (b) `ntdll.dll`/`rpcrt4.dll`/`msvcrt.dll` listed alongside it are KnownDLLs that `.local` cannot override. The `.local` branch passes the KnownDLLs gate unconditionally (`KnownDllsFilter.cs:31`), so these survive.
  - **Performance:** 36.5 minutes for a *read-only* scan, driven by `SignatureVerificationFilter.cs:57` and `PrivilegeDeltaFilter.cs:46` calling `PEAnalyzer.Analyze` **uncached, once per candidate** (≈5,000+ times), each doing a 2 MB raw read for manifest detection (`PEAnalyzer.cs:248-256`). A shared PE cache would cut this to seconds.

  *(Artifacts on disk: `safe_scan_fable.json` (19 MB), `scan_stdout.txt`.)*

### Bottom line

The enumeration engine is real and broad; the analysis and reporting layers are competent. But the tool's three marquee claims — zero false positives, ACL-validated writability, and canary-proven confirmation — do not hold in the configuration the README recommends. Run elevated, it produced **5,174 findings, 4,039 of them "HIGH," none verified, with the writability gate removing 0%.** The honest description of this tool is *a broad DLL-search-order candidate generator with a privilege-relative writability heuristic and an optional, compiler-dependent confirmation step* — not an "automated, confirmed, zero-false-positive" hijack prover. Used as a **standard user with `--lpe-only` and `--no-canary`**, it becomes a genuinely useful triage scanner; that is the opposite of the documented workflow, and the README should say so.

---

## Fix applied — attacker-relative writability (2026-06-10)

Implemented the #1 priority fix from §E: writability is now **attacker-relative** (what an unprivileged principal can write), computed independently of the elevated token the tool runs under.

### Changes (file:line)

- **`Native/NativeMethods.cs:13-14`** — added `LocalFree` P/Invoke (needed to release the security descriptor from `GetNamedSecurityInfo`).
- **`Native/AclChecker.cs`** — rewritten. Effective rights are now computed via the previously-dead `GetNamedSecurityInfoW` (`:134`) + `BuildTrusteeWithSidW` (`:177`) + `GetEffectiveRightsFromAclW` (`:179`) against the well-known low-privilege SIDs **Users S-1-5-32-545, Authenticated Users S-1-5-11, Everyone S-1-1-0** (`:40-42`) — never the current token's groups. `IsDirectoryWritableByStandardUser` (`:54`), `CanCreateDirectory` (`:71`), `CanWriteFile` (`:84`) take an optional account; a NULL DACL is treated as writable; results are memoized. A candidate's RunAsAccount is added as an extra principal **only** for the leak-proof sub-admin service accounts `LOCAL SERVICE`/`NETWORK SERVICE` (`TryResolveServiceAccount`, `:117-126`) — SYSTEM, Administrators and interactive/custom accounts are deliberately *not* resolved, so an elevated admin identity cannot leak back in.
- **`Discovery/SearchOrderCalculator.cs:83,101`** — `FindHijackablePositions` takes an optional `runAsAccount` and uses the standard-user check.
- **`Discovery/StaticDiscoveryEngine.cs:158,249,286,371,403`** — search-order, `.local`, phantom, AppInit and PATH gates use the standard-user check; the target's best-context account is threaded in (`:249,286,371`).
- **`Discovery/ETWDiscoveryEngine.cs:211,247`** — runtime image-load / failed-open gates use the standard-user check.
- **`Filters/WritabilityFilter.cs:64,68`** — the hard gate uses `IsDirectoryWritableByStandardUser` / `CanWriteFile` with the candidate's `RunAsAccount`. The pre-existing `--lpe-only` string blocklist was left untouched; no new path-string exclusions were added — the ACL decides.
- **`tests/DLLHijackHunter.Tests/`** — new xunit project (already referenced by the solution). `AclCheckerTests.cs`: (1) a System32 subdirectory is **not** writable for a standard user even when the test runs elevated; (2) System32 stays non-writable even when the current elevated user is passed as the RunAsAccount (guards the interactive-admin leak); (3) positive control — a directory granting `BUILTIN\Users:Modify` **is** writable.

### Proof

- `dotnet build -c Release -f net8.0-windows src/DLLHijackHunter/DLLHijackHunter.csproj` → **Build succeeded, 0 errors** (same single pre-existing nullable warning).
- `dotnet test tests/DLLHijackHunter.Tests` → **Passed! Failed: 0, Passed: 3**.

**Before vs. after — elevated `--profile safe`, same host (tool's own pipeline output):**

| metric | before (token-relative) | after (attacker-relative) |
|---|---:|---:|
| candidates generated | 415,740 | 0 |
| Writability hard-gate verdicts | Passed 10,350 / Failed 0 | n/a (0 candidates) |
| findings (Confirmed / High / Med / Low) | 5,174 (0 / 4,039 / 909 / 226) | 0 (0 / 0 / 0 / 0) |
| `HijackWritablePath` in `…\System32\…` | 6,189 | 0 |
| `HijackWritablePath` in `Program Files` | 2,717 | 0 |
| wall-clock | 36:34 | < 1 min |

On this host (single admin user, apps in correctly-ACL'd locations) there are genuinely **no** standard-user-writable hijack positions, so the correct result is 0 — every prior survivor was an admin-token artifact. icacls confirms `C:\Windows\System32` grants `BUILTIN\Users:(RX)` only.

**Discrimination proof (same directory + binary, tool elevated, only the ACL changed):** targeting `notepad.exe` in a temp dir granted `BUILTIN\Users:(M)` generated **114 candidates** with hijack paths inside that dir (e.g. `comctl32.dll`, `propsys.dll`, `urlmon.dll`); after revoking `Users` (leaving Admin/SYSTEM only) the same target produced **0 candidates** — proving the check tracks the ACL for an unprivileged principal, not the elevated process token.

> Note on where the reduction happens: writable positions are filtered both at discovery (`SearchOrderCalculator.FindHijackablePositions`, which by contract only emits attacker-writable positions) and re-affirmed at the `WritabilityFilter` hard gate. Because discovery now pre-filters with the standard-user model, the named hard gate shows "removed 0" — but that "0" now means *every surviving candidate is genuinely standard-user-writable*, the exact inverse of the old "removed 0" which meant *nothing was filtered because the elevated token made everything look writable*.

---

## Fixes applied — round 2 (2026-06-19)

Continued through priorities §E.2–E.5 plus the §F performance finding.

### Changes (file:line)

- **E2 — Profile `MinConfidence` no longer clobbered.** `Program.cs` now treats `--min-confidence` as an override *only when the user explicitly passes it*, via `OptionResult.IsImplicit` (`Program.cs:112-117`); `RunScan` takes a `double?` and applies it conditionally (`:138,173`). Verified empirically: `--profile safe` now reports **Min Confidence: 50%** (was 20%), `strict` reports **80%**, and `--profile safe --min-confidence 35` correctly reports **35%** (explicit override still wins).
- **E4 — "Zero False Positives" banner removed.** `BannerConstants.cs:24` tagline replaced with "Automated DLL Hijacking Discovery & Triage — Attacker-Relative Writability". No other occurrence in `src/`.
- **E4/D5 — High/Confirmed tiers reserved for proven or corroborated findings.** `TieredScorer.Score` now caps a candidate's confidence at **79 (top of Medium)** unless it has a proof signal — a fired canary, an ETW runtime load observation (`DiscoverySource == "etw"`), or a documented HijackLibs match (`IsKnownVulnerability`) — and annotates capped candidates with a "Static-only" note (`Scoring/TieredScorer.cs:46-58`). Pure static search-order heuristics can no longer present as High.
- **E5/D4 — Dead model surface removed.** Deleted the three never-set/never-read properties `BinarySHA256`, `HasWinVerifyTrust`, `ProxyExports` from `HijackCandidate` (grep-confirmed no readers/writers outside their declarations).
- **E3 — Canary architecture handling is no longer a no-op.** `CanaryDllBuilder.CompileCanary` previously ignored `is64Bit`. It now locates the VC toolchain via `vswhere` and initialises the **target** architecture (`x64`/`x86`, selected from `is64Bit`) through `vcvarsall.bat` before invoking `cl.exe` (`Canary/CanaryDllBuilder.cs:193-340`). This both honours the detected victim bitness and lets the canary build without a pre-opened developer prompt; it falls back to bare `cl.exe` on PATH (logging that its arch may not match) and logs clearly when no toolchain exists. Full dual-arch *precompiled* canary shipping (D2) remains future work.
- **§F — PE analysis memoized.** `PEAnalyzer.Analyze` now caches results by file path in a `ConcurrentDictionary` (`Discovery/PEAnalyzer.cs:9-24`). PE analysis is deterministic per path during a read-only scan and was previously re-run (2 MB raw read + authenticode verify) once per candidate across several filters — the cause of the 36-minute wall-clock. Also fixed the lone nullable warning (`CheckForManifest`, null-guard on resource directory entries); the project now builds with **0 warnings**.
- **E6 — `AppCertDlls` made real; dead enum values removed.** `AppCertDlls` was a stubbed `HijackType` never produced by any discovery path. It is now a working DLL-injection vector mirroring `AppInit_DLLs`: `StartupItemEnumerator.EnumerateAppCertDlls` reads `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`, and `StaticDiscoveryEngine` emits `HijackType.AppCertDll` candidates when the referenced DLL path is standard-user-writable. The two enum values that were never produced *and* never read anywhere — `HijackType.KnownDllBypass` and `HijackType.IFEO` — were removed (`HijackCandidate.cs`). `CWD` was kept (it still carries scaffolded logic in `LoadLibraryExFlagsFilter`/`TieredScorer`/`AttackChainCorrelator`).

### Proof

- `dotnet build -c Release -f net8.0-windows` → **Build succeeded, 0 warnings, 0 errors**.
- `dotnet test tests/DLLHijackHunter.Tests` → **Passed! Failed: 0, Passed: 3** (writability discrimination tests still green).
- CLI smoke tests confirm the profile-threshold behaviour above.

### Still open (not addressed this round)

- **D2** — ✅ done (2026-06-20): precompiled dual-arch canaries are embedded; Phase 3 confirms loads with no compiler. See "Precompiled self-locating canaries" below. Code-signing the binaries remains a release-time step (needs a cert).
- **D3** — ✅ done: KB is now data-driven and ships the full HijackLibs snapshot (see below). Only a license-terms confirmation remains for the maintainer.
- **IFEO** — *assessed, intentionally not changed.* The enumerator treats an existing Debugger value as a binary to PE-analyze, which for a *DLL-hijack* tool is actually a valid angle (the debugger EXE's own imports may be hijackable). Flagging the attacker-writable IFEO *key* instead is an EXE-redirection/persistence technique, not a DLL hijack, and would require a registry-ACL check the codebase doesn't have (IFEO lives under HKLM and needs admin to write, so the attacker-relative model would filter it on a normal host anyway). Out of scope for this tool's mission; documented in the README.

### Dead-code & redundant-cache cleanup (2026-06-19)

- **`ApiSetSchemaFilter`** — removed the no-op block that opened `…\Session Manager\ApiSetSchemaExtensions` and never read it (the §B "registry read is theater" finding); dropped the now-unused `Microsoft.Win32` import. Prefix matching + System32 stub enumeration is unchanged.
- **Redundant local PE caches removed** — `LoadLibraryExFlagsFilter` and `WinSxSManifestFilter` each kept a private `Dictionary<string, PEAnalysisResult>`; these are now dead weight since `PEAnalyzer.Analyze` is globally memoized (round 2). Both now call `Analyze` directly.

Build **0 warnings**; tests **7/7**.

### Dead enum surface removed (done, 2026-06-19)

Closed the §D4 "collapse dead enum/type surface" item for the never-produced types:
- **`HijackType.CWD`** removed — it was read in three places but never assigned (no static CWD-launch detection exists). References cleaned up in `Scoring/TieredScorer.cs` (stealth switch), `Scoring/AttackChainCorrelator.cs` (Direct-Path filter), and `Filters/LoadLibraryExFlagsFilter.cs` (the unreachable `SetDllDirectory`→CWD branch was collapsed). README marks CWD as "Planned".
- **`TriggerType.WMI`** removed — never assigned; the only references were priority-switch arms in `Discovery/StaticDiscoveryEngine.cs` and `Filters/FilterPipeline.cs` (both now fall through to the default). The unrelated `"WMI"` phantom-DLL category in `phantom_dlls.json` is untouched.
- (`HijackType.KnownDllBypass`/`IFEO` were already removed in the previous round.)

Build: **0 warnings, 0 errors**; tests **3/3**.

### Knowledge base made data-driven (D3 architecture, 2026-06-19)

`KnowledgeBaseEngine` no longer hardcodes its map. The dataset now lives in an embedded JSON resource (`Resources/hijacklibs.json`, schema `hijacklibs-subset-v1`) and is loaded lazily; the existing 10 entries were migrated faithfully. Expanding coverage — or dropping in a generated full HijackLibs snapshot — is now a **data change with no code edits**. A malformed/missing resource degrades to an empty KB rather than crashing. Added `KnowledgeBaseEngine.EntryCount` for diagnostics.

- Files: `Discovery/KnowledgeBaseEngine.cs` (rewritten, data-driven), `Resources/hijacklibs.json` (new, embedded via `DLLHijackHunter.csproj`).
- Tests: `tests/DLLHijackHunter.Tests/KnowledgeBaseEngineTests.cs` (new) — verifies the embedded resource loads (`EntryCount > 0`), a known combo matches and returns a reference, matching is case-insensitive, and unknown combos don't match. The test project embeds the same JSON under the engine's exact manifest name via `<LogicalName>`.
- Build: **0 warnings, 0 errors**; tests **7/7** (3 AclChecker + 4 KB).

The remaining D3 work is purely sourcing: vendoring a complete, license-cleared HijackLibs/LOLBAS snapshot (≈400+ entries) and a refresh mechanism. The README already states the KB is a curated subset, not a full mirror.

### Full HijackLibs dataset vendored (D3 complete, 2026-06-19)

Replaced the 10-entry hand-made subset with the **full HijackLibs export** fetched from `https://hijacklibs.net/api/hijacklibs.json` (590 DLL-centric entries → **714 distinct vulnerable binaries / 2,331 binary↔DLL mappings**), vendored as `Resources/hijacklibs.json` (≈923 KB, embedded).

- `KnowledgeBaseEngine.LoadDatabase` rewritten to parse the **native HijackLibs schema**: each entry's `Name` is the hijackable DLL and each `VulnerableExecutables[].Path` is a susceptible EXE; these are inverted into the `(binaryName → dll → url)` lookup `CheckKnowledgeBase` needs. The loader also accepts a `{ "entries": [...] }` wrapper for a future provenance-stamped generator. Basenames without a file extension (e.g. an env-var-only path fragment) are skipped.
- **Refresh is a pure data drop-in:** re-download the same URL over `Resources/hijacklibs.json` — no code change.
- README updated: KB now described as a bundled HijackLibs snapshot (~590 entries) with attribution and the refresh URL; comparison-table footnote ⁶ corrected.
- Tests updated to real combos present in the dataset (`AcroDist.exe`+`acrodistdll.dll`) and assert `EntryCount > 100`. Build **0 warnings**; tests **7/7**.

> **Caveat for the maintainer:** confirm HijackLibs' license/attribution terms are compatible with redistributing the dataset inside this MIT project before publishing a release. The data is attributed to the HijackLibs project in the README; verify that satisfies their terms.

### Precompiled self-locating canaries (D2 complete, 2026-06-20)

Closed §D2 / §E3's remaining half: **Phase 3 now confirms a DLL load with no compiler present.**

The blocker for a precompiled canary was that the legacy build baked per-run state (canary id, confirm path) into the C source at compile time. The fix makes the canary **self-locating**: at `DLL_PROCESS_ATTACH` it reads its own loaded module path (`GetModuleFileNameA`), hashes it (FNV-1a 64, A–Z folded to a–z), and writes `%ProgramData%\DLLHijackHunter\canary_<hash>.confirm`. The scanner computes the **same** hash from the path it deployed to and polls for that file — so a single binary per architecture serves every candidate, identity coming from the deploy location rather than a compile-time constant.

- **New auditable source** `Resources/canary_src.c` — the self-locating canary (kernel32 + advapi32; same token/integrity/SeDebug enrichment as the legacy generated source). Compiled once to **`Resources/canary_x64.dll`** and **`Resources/canary_x86.dll`** (`/MT`, static CRT → no ucrtbase/vcruntime dependency on the victim), both embedded (`DLLHijackHunter.csproj`). Reproducible via `Resources/build_canary.bat` (needs MSVC; the scanner does not).
- **`Canary/CanaryDllBuilder.cs`** rewritten:
  - `DeployHash` / `GetConfirmPath` mirror the C hash byte-for-byte.
  - `BuildCanary(…, string deployPath)` routes: (1) if the real DLL exists with exports **and** MSVC is available → compile a functional export-forwarding proxy; (2) else → extract the embedded precompiled canary for the victim bitness (default, no compiler); (3) last resort → compile a non-proxy canary from the bundled source. `GenerateCanarySource` now loads `canary_src.c` from the embedded resource (so the proxy variant cannot drift from the precompiled binary) and only appends the export `#pragma`s.
- **`Canary/CanaryEngine.cs`** — passes the deploy path; clears any stale confirm file before deploying (so a prior run can't be mistaken for this one); notes when a proxy was wanted but the precompiled non-proxy was used (confirms the load, host may crash); the "no compiler" message now only fires if the embedded binary is somehow absent.

**Proof (this host has MSVC but no installed Windows SDK; SDK headers/libs pulled from the official `Microsoft.Windows.SDK.CPP*` NuGet packages to compile):**
- Both DLLs verified as correct PE machine types (x64 → 0x8664, x86 → 0x14c) and embedded under `DLLHijackHunter.Resources.canary_x{64,86}.dll`.
- **Cross-language end-to-end:** copied `canary_x64.dll` to an arbitrary temp path, `LoadLibrary`'d it, and the canary wrote exactly `canary_ff18a7bf673bd7c2.confirm` — the **same** name the real C# `DeployHash` predicted for that path — with full enrichment (`USER=…`, `INTEGRITY=Medium`, `SE_DEBUG=NO`). Proves C ↔ C# hash agreement and that self-location + confirmation work with zero compiler at scan time.
- `dotnet build -c Release -f net8.0-windows` → **0 warnings, 0 errors**; `dotnet test` → **7/7**.

Remaining: **code-signing** the embedded canaries (needs a certificate; release-time step) and optional precompiled *proxy* variants (export forwarding is inherently per-DLL, so it stays compiler-backed).

### README honesty pass (done, 2026-06-19)

`README.md` updated to match implemented reality:
- Hijack-type table now has a **Status** column; `KnownDLL Bypass`/`IFEO` rows removed (enum values deleted), `AppCert DLLs` marked Implemented, `CWD` marked "Planned — not currently produced".
- Canary section states the **MSVC toolchain requirement** and the new `vswhere`/`vcvarsall` architecture-matched build; notes findings stay `NotTested` without it.
- Knowledge base honestly described as a **~10-app bundled dictionary, not a full HijackLibs mirror**.
- Hard-gate writability described as **attacker-relative** (independent of the tool's token).
- CLI options gained `--lpe-only` / `--log-file`; the `--min-confidence` default note corrected (profile threshold applies unless explicitly overridden).
- Comparison table ✅s annotated with six footnotes (canary toolchain dependency, FP-reduction scope, persistence heuristic, experimental proxy, trigger coverage, KB size).
- New **Tier gating** + **Recommended triage configuration** subsections under Scoring (standard-user `--lpe-only` is the most trustworthy LPE config).

### Dynamic load-order verification probe (§C, 2026-06-20)

Closed the §C gap *"No actual dynamic load probe (LoadLibraryEx) to verify search order — declared P/Invokes go unused."* The previously-dead `LoadLibraryExW`/`FreeLibrary`/`GetModuleFileNameW` imports are now used.

New opt-in `--verify-load` phase (between filtering and canary) that adjudicates each candidate's search-order claim with the **real Windows loader** instead of the static calculator:

- For Phantom/SearchOrder/SideLoad candidates it places a benign probe (the embedded x64 canary) at the writable hijack position and, **in a short-lived child process** (`--resolve-probe <dir> <dll>`), calls `AddDllDirectory` + `LoadLibraryExW` with the `LOAD_LIBRARY_SEARCH_*` flags, then `GetModuleFileNameW` to see which path the loader actually picked.
  - resolves to the writable position → **Wins** (treated as a proof signal — may reach High; +10 confidence).
  - resolves to a KnownDLL/System32/SxS path → **LosesToProtected** (strong false-positive signal — −40 confidence, never High). This is the loader catching exactly the `.local`/KnownDLL false positives the original audit flagged (the `ntdll.dll`-beside-`APHostService` class).
- Child process (not in-process) for two reasons: a name already loaded into the scanner would short-circuit `LoadLibraryEx` and mislead; and it isolates any load side effect/crash. Runs as a **standard user** — no elevation, no victim trigger.
- DotLocal/EnvPath/AppInit/AppCert use different load mechanics, so they are **Skipped** (the modern `LOAD_LIBRARY_SEARCH` ordering doesn't faithfully model them).
- The probe is placed, resolved, then removed; any pre-existing file is backed up and restored.

Files: `Native/NativeMethods.cs` (added `AddDllDirectory`/`RemoveDllDirectory` + `LOAD_LIBRARY_SEARCH_USER_DIRS`/`DEFAULT_DIRS`), `Verification/LoadProbe.cs` (new — child resolver + parent orchestration), `Models/HijackCandidate.cs` (`LoadProbeResult` enum + fields), `Models/ScanProfile.cs` (`VerifyLoad`, `LoadProbeTimeoutSeconds`), `Canary/CanaryDllBuilder.cs` (`TryGetProbeDll`), `Scoring/TieredScorer.cs` (wins=proof, loses=−40), `Program.cs` (hidden child mode + `--verify-load` + phase 2.5). README documents the flag and its semantics/safety.

**Proof:**
- Empirically established loader semantics first: with a planted probe, a **KnownDLL resolves to System32** (correctly rejected) while a **non-KnownDLL/phantom resolves to the writable position** (correctly won) — verified both in a prototype and in the built exe's child mode (phantom→WIN, kernel32→System32, unplanted→NOTRESOLVED).
- Parent orchestration (place → spawn → interpret → remove/restore) validated against the real exe child, including backup/restore integrity.
- `dotnet build` → **0 warnings, 0 errors**; `dotnet test` → **10/10** (added 3 scorer tests: static-only capped below High; probe-win reaches High; probe-loss demoted and never High).

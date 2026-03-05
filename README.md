<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows-blue?style=for-the-badge&logo=windows" />
  <img src="https://img.shields.io/badge/.NET-8.0-purple?style=for-the-badge&logo=dotnet" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Version-1.2.0-orange?style=for-the-badge" />
</p>

<h1 align="center">DLLHijackHunter</h1>
<h4 align="center">By GhostVector Academy</h4>

<p align="center">
  <strong>Automated DLL Hijacking Discovery, Validation, and Confirmation</strong><br/>
  <em>The only tool that proves hijacks actually work before reporting them.</em>
</p>

---

## 🔍 Overview

**DLLHijackHunter** is an automated Windows DLL hijacking detection tool that goes beyond static analysis. It discovers, validates, and confirms DLL hijacking opportunities using a multi-phase pipeline:

1. **Discovery** — Enumerates binaries across services, scheduled tasks, startup items, COM objects, and AutoElevate UAC bypass vectors
2. **Filtration** — Eliminates false positives through 8 intelligent gates (hard gates + confidence-adjusting soft gates)
3. **Canary Confirmation** — Deploys a harmless canary DLL and triggers the binary to prove the hijack works
4. **Scoring & Reporting** — Ranks findings by exploitability with a tiered confidence system

> Every existing DLL hijacking tool stops at "this DLL might be hijackable." DLLHijackHunter actually proves it, reports the achieved privilege level, and identifies whether it survives reboot.

---

## 🏗️ Architecture

```mermaid
flowchart TB
    subgraph Phase1["Phase 1: Discovery"]
        SE["Static Engine<br/>Services, Tasks, Startup,<br/>COM, Run Keys"]
        AE["AutoElevate Engine<br/>Manifest + COM UAC Bypass"]
        PE["PE Analyzer<br/>Import Tables, Delay Loads,<br/>Manifests, Exports"]
        ETW["ETW Engine<br/>Real-time DLL Load<br/>Monitoring"]
        SO["Search Order<br/>Calculator"]
    end

    subgraph Phase2["Phase 2: Filter Pipeline"]
        direction LR
        HG["Hard Gates<br/>(Binary Kill)"]
        SG["Soft Gates<br/>(Confidence Adj.)"]
    end

    subgraph Phase3["Phase 3: Canary"]
        CB["Canary DLL Builder"]
        TE["Trigger Executor"]
        VF["Verification"]
    end

    subgraph Phase4["Phase 4: Output"]
        SC["Tiered Scorer"]
        RC["Console Report"]
        RJ["JSON Report"]
        RH["HTML Report"]
    end

    SE --> PE --> SO
    AE --> PE
    ETW --> SO
    SO --> Phase2
    HG --> SG
    Phase2 --> Phase3
    CB --> TE --> VF
    Phase3 --> Phase4

    style Phase1 fill:#1a1a2e,stroke:#58a6ff,color:#c9d1d9
    style Phase2 fill:#1a1a2e,stroke:#d29922,color:#c9d1d9
    style Phase3 fill:#1a1a2e,stroke:#f85149,color:#c9d1d9
    style Phase4 fill:#1a1a2e,stroke:#3fb950,color:#c9d1d9
```

---

## 🎯 Key Features

### Hijack Type Coverage

| Type | Description | Stealth |
|---|---|---|
| **Phantom** | DLL doesn't exist anywhere on disk — cleanest hijack | High |
| **Search Order** | Place DLL earlier in the Windows search order | High |
| **Side-Loading** | Abuse legitimate app loading DLLs from its directory | High |
| **.local Redirect** | Hijack via `.local` directory redirection | High |
| **KnownDLL Bypass** | Bypass KnownDLLs via .local or WoW64 | Medium |
| **ENV PATH** | Writable directory in system PATH | Low |
| **CWD** | Current Working Directory hijack | Low |
| **AppInit DLLs** | AppInit_DLLs registry abuse | Low |
| **IFEO** | Image File Execution Options debugger | Medium |
| **AppCert DLLs** | AppCertDLLs registry hijack | Low |

### UAC Bypass Discovery

DLLHijackHunter includes dedicated UAC bypass detection:

- **Manifest AutoElevate** — Scans `System32` and `SysWOW64` for EXEs with `<autoElevate>true</autoElevate>` in their embedded manifests
- **COM AutoElevation** — Scans `HKLM\SOFTWARE\Classes\CLSID` for COM objects with `Elevation\Enabled=1` (covers techniques like Fodhelper, CMSTPLUA, and similar)
- **Side-Load Simulation** — For AutoElevate binaries that don't call `SetDllDirectory` or `SetDefaultDllDirectories`, simulates the "copy EXE to writable folder + drop DLL" attack vector

### Filter Pipeline

The pipeline eliminates false positives through two stages:

**Hard Gates** (binary elimination):
- **API Set Schema** — Removes virtual API set DLLs (`api-ms-*`, `ext-ms-*`)
- **Known DLLs** — Removes Windows-protected KnownDLLs from registry
- **Writability** — ACL-based check; only keeps candidates where the hijack path is writable

**Soft Gates** (confidence adjustment, -10% to -30% each):
- **WinSxS Manifest** — Penalizes if DLL is covered by Side-by-Side manifest
- **Privilege Delta** — Evaluates if hijack provides useful privilege escalation
- **LoadLibraryEx Flags** — Checks for `LOAD_LIBRARY_SEARCH_*` mitigations
- **Signature Verification** — Checks if the binary validates DLL signatures
- **Error Handled Load** — Detects if failed DLL loads are gracefully handled

### Canary Confirmation

Instead of guessing, DLLHijackHunter proves hijacks work:

```mermaid
sequenceDiagram
    participant H as DLLHijackHunter
    participant B as Canary DLL Builder
    participant T as Trigger Executor
    participant V as Victim Binary

    H->>B: Build canary DLL (exports proxied)
    B->>B: Compile with MSVC/MinGW
    B-->>H: canary.dll + confirmation pipe
    H->>H: Place DLL at hijack path
    H->>T: Trigger binary execution
    T->>V: Start service / Run task / COM activate
    V->>V: Loads canary DLL
    V-->>H: Named pipe callback:<br/>PID, privilege, integrity level
    H->>H: Record: CONFIRMED
    H->>H: Cleanup canary DLL
```

The canary DLL:
- Proxy-exports all original functions (application keeps working)
- Reports back via named pipe: achieved privilege, integrity level, SeDebug status
- Self-cleans after confirmation
- Contains no malicious code — purely a detection mechanism

---

## ⚡ Comparison

| Feature | **DLLHijackHunter** | Robber | DLLSpy | WinPEAS | Procmon |
|---|:---:|:---:|:---:|:---:|:---:|
| Automated discovery | ✅ | ✅ | ✅ | ✅ | ❌ |
| Phantom DLL detection | ✅ | ❌ | ✅ | ❌ | ✅ |
| Search order analysis | ✅ | ❌ | ❌ | ❌ | ❌ |
| ACL-based writability check | ✅ | Partial | ❌ | Basic | ❌ |
| ETW real-time monitoring | ✅ | ❌ | ❌ | ❌ | ✅ |
| Canary confirmation | ✅ | ❌ | ❌ | ❌ | ❌ |
| Privilege escalation check | ✅ | ❌ | ❌ | ❌ | ❌ |
| UAC bypass discovery | ✅ | ❌ | ❌ | ❌ | ❌ |
| False positive elimination | 8 filters | None | Basic | None | None |
| Reboot persistence check | ✅ | ❌ | ❌ | ❌ | ❌ |
| Proxy DLL generation | ✅ | ❌ | ❌ | ❌ | ❌ |
| Confidence scoring | 5-tier | ❌ | ❌ | ❌ | ❌ |
| Auto trigger (svc/task/COM) | ✅ | ❌ | ❌ | ❌ | ❌ |
| HTML/JSON reporting | ✅ | ❌ | ❌ | TXT | ❌ |
| Target-specific scanning | ✅ | ❌ | ❌ | ❌ | ✅ |
| Self-contained binary | ✅ | ❌ | ❌ | ✅ | ❌ |

---

## 🚀 Usage

### Prerequisites

- **Windows 10/11** or **Windows Server 2016+**
- **.NET 8.0 Runtime** (or use self-contained build)
- **Administrator privileges** recommended (required for ETW, canary, service triggers)

### Build

```powershell
# Clone
git clone https://github.com/ghostvectoracademy/DLLHijackingHunter.git
cd DLLHijackingHunter

# Build (self-contained single file)
dotnet publish src/DLLHijackHunter/DLLHijackHunter.csproj `
    -c Release -r win-x64 --self-contained `
    -p:PublishSingleFile=true -o ./publish

# Or use the build script
.\build.ps1
```

### Quick Start

```powershell
# Full aggressive scan (recommended, requires admin)
.\DLLHijackHunter.exe --profile aggressive

# Safe scan (no file drops, no triggers — safe for production)
.\DLLHijackHunter.exe --profile safe

# UAC bypass focused scan
.\DLLHijackHunter.exe --profile uac-bypass

# Target a specific binary
.\DLLHijackHunter.exe --target "C:\Program Files\MyApp\app.exe"

# Target by filename (partial match)
.\DLLHijackHunter.exe --target notepad.exe

# Red team mode (only confirmed, exploitable findings)
.\DLLHijackHunter.exe --profile redteam --format json -o report.json
```

### CLI Options

```
DLLHijackHunter — Automated DLL Hijacking Detection

Options:
  -p, --profile <profile>        Scan profile [default: aggressive]
                                   aggressive | strict | safe | redteam | uac-bypass
  -o, --output <path>            Output file path (auto-detects format)
  -f, --format <format>          Output format [default: console]
                                   console | json | html
  -t, --target <target>          Target specific binary, directory, or filename
      --min-confidence <value>   Minimum confidence threshold 0-100 [default: 20]
      --no-canary                Disable canary confirmation (safe for prod)
      --no-etw                   Disable ETW runtime discovery
      --confirmed-only           Only show canary-confirmed findings
  -v, --verbose                  Verbose output
```

### Scan Profiles

| Profile | Use Case | Canary | ETW | UAC Bypass | Min Confidence | Triggers |
|---|---|:---:|:---:|:---:|:---:|---|
| **aggressive** | Full audit, lab environments | ✅ | ✅ | ✅ | 15% | Services, Tasks, COM |
| **strict** | High-confidence findings only | ✅ | ✅ | ❌ | 80% | Services, Tasks |
| **safe** | Production systems, read-only | ❌ | ❌ | ❌ | 50% | None |
| **redteam** | Confirmed exploitable only | ✅ | ✅ | ❌ | 50% | Services, Tasks, COM |
| **uac-bypass** | UAC bypass vectors only | ❌ | ❌ | ✅ | 20% | AutoElevate only |

---

## 📊 Scoring

Each finding receives three scores:

```mermaid
flowchart LR
    C["Confidence<br/>0-100%"] --> F["Final Score"]
    I["Impact<br/>0-10"] --> F
    F --> T["Tier Assignment"]
    T --> T1["CONFIRMED<br/>Canary proven"]
    T --> T2["HIGH<br/>≥80% confidence"]
    T --> T3["MEDIUM<br/>50-79%"]
    T --> T4["LOW<br/>20-49%"]

    style T1 fill:#f85149,color:white
    style T2 fill:#d29922,color:white
    style T3 fill:#e3b341,color:#1c1e21
    style T4 fill:#8b949e,color:white
```

**Impact Score** (0-10) is composed of:

| Component | Range | Details |
|---|---|---|
| Privilege gained | 0–4 | SYSTEM = 4, Admin/LocalService = 3, User = 1 |
| Trigger reliability | 0–3 | Auto-start service = 3, UAC bypass = 2.8, Frequent task = 2.5, Startup = 2 |
| Stealth | 0–2 | Phantom = 2, .local = 1.8, Search order = 1.5, Side-load = 1.5 |
| Persistence bonus | +1 | Survives reboot |

**Final Score** = `(Confidence × 0.4 + Impact × 0.6) × 10`, clamped to 0–10.

---

## 🛡️ Safety

DLLHijackHunter is a detection tool, not an exploitation framework:

- Canary DLLs contain no malicious payload — they only report metadata via named pipe
- All canary files are automatically cleaned up after testing
- Proxy exports keep the target application fully functional
- Use `--profile safe` for production systems (no file writes, no triggers)
- Always obtain proper authorization before scanning systems you do not own

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">
  <strong>Built by <a href="https://github.com/ghostvectoracademy">GhostVector Academy</a></strong><br/>
  <em>Elite Cybersecurity with Zero Paywalls.</em>
</p>

# Contributing to DLLHijackHunter

First off, thanks for considering contributing to **DLLHijackHunter**! 🎉 Every contribution helps make this tool better for the security community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Coding Guidelines](#coding-guidelines)
- [Submitting Changes](#submitting-changes)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)

---

## Code of Conduct

This project follows our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold a welcoming, respectful environment.

---

## How Can I Contribute?

There are many ways to contribute beyond writing code:

| Contribution Type | Examples |
|---|---|
| **Bug Reports** | Found a false positive? Crash on a specific config? |
| **Feature Requests** | New hijack type, output format, filter idea |
| **Code** | Bug fixes, new features, performance improvements |
| **Documentation** | Fix typos, improve explanations, add examples |
| **Testing** | Run scans on different Windows versions and report results |
| **Canary Templates** | New canary DLL templates for edge cases |

---

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/DLLHijackingHunter.git
   cd DLLHijackingHunter
   ```
3. **Create a branch** for your work:
   ```bash
   git checkout -b feature/your-feature-name
   ```

---

## Development Setup

### Prerequisites

- **Windows 10/11** (for testing — the tool is Windows-specific)
- **.NET 8.0 SDK** — [Download](https://dotnet.microsoft.com/en-us/download/dotnet/8.0)
- **Visual Studio 2022** or **VS Code** with C# extensions (recommended)
- **Administrator privileges** for running canary tests

### Build

```powershell
# Restore and build
dotnet build src/DLLHijackHunter/DLLHijackHunter.csproj -c Debug

# Run
dotnet run --project src/DLLHijackHunter/DLLHijackHunter.csproj -- --profile safe

# Publish self-contained binary
dotnet publish src/DLLHijackHunter/DLLHijackHunter.csproj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o ./publish
```

### Project Structure

```
src/DLLHijackHunter/
├── Discovery/      # Static + ETW engines, PE analysis
├── Filters/        # Hard gates + soft gates
├── Canary/         # DLL builder, trigger, confirmation
├── Models/         # Data models, profiles, enums
├── Scoring/        # Tiered scoring algorithm
├── Reporting/      # Console, JSON, HTML reports
├── Native/         # P/Invoke, ACL checks, tokens
└── Program.cs      # CLI entry point
```

---

## Coding Guidelines

### Style

- Follow existing code conventions in the project.
- Use **PascalCase** for public members, **camelCase** for locals.
- Add XML doc comments (`///`) for all public types and methods.
- Keep methods focused — prefer small, single-responsibility methods.

### Commits

- Write clear, concise commit messages.
- Use the present tense: `"Add phantom DLL filter"` not `"Added phantom DLL filter"`.
- Reference issues where applicable: `"Fix #42 — false positive on api-ms-* DLLs"`.

### Testing

- Test your changes on at least one Windows version before submitting.
- For new filters or hijack types, include sample scenarios in your PR description.
- Use `--profile safe` for non-destructive testing.

---

## Submitting Changes

1. **Ensure your code builds** without warnings:
   ```powershell
   dotnet build src/DLLHijackHunter/DLLHijackHunter.csproj -c Release
   ```
2. **Push** your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
3. **Open a Pull Request** against `main` on the upstream repository.
4. Fill out the **PR template** — describe what you changed and why.
5. Be responsive to code review feedback.

### PR Merge Criteria

- ✅ Builds without warnings
- ✅ Doesn't break existing functionality
- ✅ Follows coding guidelines
- ✅ Has a clear description and rationale
- ✅ Security-sensitive changes reviewed by a maintainer

---

## Reporting Bugs

Use the [Bug Report template](https://github.com/ghostvectoracademy/DLLHijackingHunter/issues/new?template=bug_report.md) and include:

- **OS version** (e.g., Windows 11 23H2)
- **DLLHijackHunter version** or commit hash
- **Command line** used
- **Expected vs. actual behavior**
- **Relevant log output** (use `--verbose`)

---

## Suggesting Features

Use the [Feature Request template](https://github.com/ghostvectoracademy/DLLHijackingHunter/issues/new?template=feature_request.md) and describe:

- **The problem** your feature would solve
- **Your proposed solution**
- **Alternatives** you've considered

---

## Security Vulnerabilities

If you discover a security vulnerability, **do NOT open a public issue**. Please see our [Security Policy](SECURITY.md) for responsible disclosure instructions.

---

<p align="center">
  <strong>Thank you for helping make DLLHijackHunter better! 🔍</strong><br/>
  <em>Built by <a href="https://github.com/ghostvectoracademy">GhostVector Academy</a></em>
</p>

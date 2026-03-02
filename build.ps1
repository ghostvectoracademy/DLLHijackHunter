# build.ps1 — Build the complete tool
param(
    [switch]$Release,
    [switch]$SingleFile
)

$config = if ($Release) { "Release" } else { "Debug" }

Write-Host "Building DLLHijackHunter ($config)..." -ForegroundColor Cyan

# Restore packages
dotnet restore src/DLLHijackHunter/DLLHijackHunter.csproj

# Build
if ($SingleFile) {
    dotnet publish src/DLLHijackHunter/DLLHijackHunter.csproj `
        -c $config `
        -r win-x64 `
        --self-contained `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -o ./build

    Write-Host "Single-file binary: ./build/DLLHijackHunter.exe" -ForegroundColor Green
} else {
    dotnet build src/DLLHijackHunter/DLLHijackHunter.csproj -c $config -o ./build

    Write-Host "Build output: ./build/" -ForegroundColor Green
}

Write-Host ""
Write-Host "Usage:" -ForegroundColor Yellow
Write-Host "  ./build/DLLHijackHunter.exe --profile aggressive"
Write-Host "  ./build/DLLHijackHunter.exe --profile safe --no-canary --no-etw"
Write-Host "  ./build/DLLHijackHunter.exe --profile redteam --confirmed-only -o report.html"
Write-Host "  ./build/DLLHijackHunter.exe --profile strict --format json -o results.json"
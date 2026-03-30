$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

Write-Host "Cleaning previous build output..."
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }

Write-Host "Building TorTraceAnalyzer executable..."
python -m PyInstaller --clean --noconfirm TorTraceAnalyzer.spec

if (-not (Test-Path ".\\dist\\TorTraceAnalyzer.exe")) {
    throw "Build finished but dist\\TorTraceAnalyzer.exe was not created."
}

Write-Host ""
Write-Host "Build complete."
Write-Host "Executable: $root\\dist\\TorTraceAnalyzer.exe"

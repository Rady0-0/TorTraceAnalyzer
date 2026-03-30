$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

powershell -ExecutionPolicy Bypass -File .\scripts\build_exe.ps1

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$releaseRoot = Join-Path $root "release"
$packageDir = Join-Path $releaseRoot ("TorTraceAnalyzer_Portable_" + $timestamp)
$sampleDir = Join-Path $packageDir "sample_inputs"
$zipPath = $packageDir + ".zip"

if (Test-Path $packageDir) { Remove-Item -Recurse -Force $packageDir }
New-Item -ItemType Directory -Force $packageDir | Out-Null
New-Item -ItemType Directory -Force $sampleDir | Out-Null

Copy-Item .\dist\TorTraceAnalyzer.exe $packageDir
Copy-Item .\docs\QUICK_START.txt $packageDir
Copy-Item .\samples\* $sampleDir -Recurse -Force

if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
Compress-Archive -Path (Join-Path $packageDir "*") -DestinationPath $zipPath

Write-Host ""
Write-Host "Portable package created: $packageDir"
Write-Host "Zip package created: $zipPath"

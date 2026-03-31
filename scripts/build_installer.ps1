$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

function Get-IsccPath {
    if ($env:ISCC_PATH -and (Test-Path $env:ISCC_PATH)) {
        return $env:ISCC_PATH
    }

    $candidates = @(
        "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        "C:\Program Files\Inno Setup 6\ISCC.exe",
        (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe")
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    throw "Inno Setup compiler (ISCC.exe) was not found. Install Inno Setup 6 or set ISCC_PATH."
}

function Get-SignToolPath {
    if ($env:SIGNTOOL_PATH -and (Test-Path $env:SIGNTOOL_PATH)) {
        return $env:SIGNTOOL_PATH
    }

    $kitRoots = @(
        "C:\Program Files (x86)\Windows Kits\10\bin",
        "C:\Program Files\Windows Kits\10\bin"
    )

    foreach ($kitRoot in $kitRoots) {
        if (-not (Test-Path $kitRoot)) {
            continue
        }

        $candidate = Get-ChildItem -Path $kitRoot -Filter "signtool.exe" -Recurse -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -First 1

        if ($candidate) {
            return $candidate.FullName
        }
    }

    return $null
}

function Get-AppVersion {
    if ($env:TORTRACE_APP_VERSION) {
        return $env:TORTRACE_APP_VERSION.TrimStart("v")
    }

    try {
        $tag = (git describe --tags --abbrev=0 2>$null).Trim()
        if ($tag) {
            return $tag.TrimStart("v")
        }
    } catch {
    }

    return "1.0.0"
}

function Invoke-CodeSign {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetPath
    )

    $signtoolPath = Get-SignToolPath
    $certificatePath = $env:CODESIGN_CERT_FILE
    $certificatePassword = $env:CODESIGN_CERT_PASSWORD
    $timestampUrl = if ($env:TIMESTAMP_URL) { $env:TIMESTAMP_URL } else { "http://timestamp.digicert.com" }

    if (-not $signtoolPath -or -not (Test-Path $signtoolPath) -or -not $certificatePath -or -not (Test-Path $certificatePath) -or -not $certificatePassword) {
        Write-Host "Skipping code signing for $TargetPath (missing signtool or certificate settings)." -ForegroundColor Yellow
        return $false
    }

    & $signtoolPath sign /fd SHA256 /f $certificatePath /p $certificatePassword /tr $timestampUrl /td SHA256 $TargetPath
    Write-Host "Signed $TargetPath"
    return $true
}

Write-Host "Building TorTraceAnalyzer EXE..."
powershell -ExecutionPolicy Bypass -File .\scripts\build_exe.ps1

$releaseRoot = Join-Path $root "release"
if (-not (Test-Path $releaseRoot)) {
    New-Item -ItemType Directory -Force $releaseRoot | Out-Null
}

Get-ChildItem $releaseRoot -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "TorTraceAnalyzer_Setup_*" } |
    Remove-Item -Force

$appVersion = Get-AppVersion
$isccPath = Get-IsccPath
$issPath = Join-Path $root "installer\TorTraceAnalyzer.iss"
$exePath = Join-Path $root "dist\TorTraceAnalyzer.exe"

Invoke-CodeSign -TargetPath $exePath | Out-Null

Write-Host "Building Windows installer..."
& $isccPath "/DAppVersion=$appVersion" "/DRepoRoot=$root" $issPath

$installerPath = Join-Path $releaseRoot ("TorTraceAnalyzer_Setup_" + $appVersion + ".exe")
if (-not (Test-Path $installerPath)) {
    throw "Installer build finished but $installerPath was not created."
}

Invoke-CodeSign -TargetPath $installerPath | Out-Null

Write-Host ""
Write-Host "Installer build complete."
Write-Host "Installer: $installerPath"

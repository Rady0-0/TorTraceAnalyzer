Code Signing
============

TorTraceAnalyzer now includes a signing-ready Windows installer pipeline.

What is required
- Inno Setup 6
- A code-signing certificate file, such as `.pfx`
- `signtool.exe`
- A certificate password

Environment variables used by `scripts/build_installer.ps1`
- `SIGNTOOL_PATH`
- `CODESIGN_CERT_FILE`
- `CODESIGN_CERT_PASSWORD`
- `TIMESTAMP_URL` (optional)
- `TORTRACE_APP_VERSION` (optional)

Example
```powershell
$env:SIGNTOOL_PATH="C:\Program Files (x86)\Windows Kits\10\App Certification Kit\signtool.exe"
$env:CODESIGN_CERT_FILE="C:\certs\TorTraceAnalyzer.pfx"
$env:CODESIGN_CERT_PASSWORD="your-password"
$env:TIMESTAMP_URL="http://timestamp.digicert.com"
$env:TORTRACE_APP_VERSION="1.0.0"
powershell -ExecutionPolicy Bypass -File .\scripts\build_installer.ps1
```

Behavior
- The installer script auto-detects `ISCC.exe` and also searches common Windows SDK locations for `signtool.exe`.
- If signing settings are present, the EXE and installer are signed.
- If signing settings are missing, the installer still builds, but remains unsigned.

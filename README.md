# TorTraceAnalyzer

TorTraceAnalyzer is a Python-based digital forensics tool for detecting and correlating Tor activity across multiple evidence layers. It combines disk-style artifacts, memory-style artifacts, network indicators, packet captures, correlation logic, timeline reconstruction, and reporting in a desktop interface built with CustomTkinter.

## What the tool does

- Parses evidence files and folders recursively.
- Runs multi-layer analysis across memory, system, network, application, and transport indicators.
- Normalizes detections into a single pipeline for correlation and FCI scoring.
- Reconstructs a MACB-style timeline from available timestamps.
- Exports reports to TXT, CSV, Excel, JSON, and PDF.
- Packages into a portable Windows EXE for users who do not have Python installed.
- Supports analysis cancellation from the GUI when a large evidence set needs to be stopped safely.

## Supported input files

You can provide either individual files or folders containing mixed evidence.

Accepted file types:

- `.txt`, `.log`, `.csv`
- `.json`
- `.xlsx`, `.xls`
- `.docx`
- `.html`, `.htm`
- `.raw`, `.mem`, `.dmp`, `.bin`
- `.e01`
- `.pcap`, `.pcapng`

Notes:

- `.e01` is recognized as a disk-image indicator but is not deeply parsed directly.
- `.pcap` and `.pcapng` are analyzed offline from the file itself. Live sniffing is not required.
- For best results, use exported reports from tools such as Wireshark, Volatility, FTK Imager, or Autopsy.

## Analysis pipeline

The project now follows this pipeline consistently:

`file_parser -> analysis modules -> all_detections -> correlation -> FCI -> timeline/report -> GUI`

Each detection is normalized into the same structure:

```python
{
    "layer": "...",
    "file_name": "...",
    "message": "...",
    "evidence_match": "...",
    "disk_timestamps": {
        "modified": "...",
        "created": "...",
        "accessed": "..."
    }
}
```

## GUI overview

- `DASHBOARD`: Overall summary, FCI, correlation, detected artifacts, engine messages.
- `MEMORY`, `SYSTEM`, `NETWORK`, `APPLICATION`, `TRANSPORT`: Layer-specific findings shown in compact evidence tables with a details pane.
- `TIMELINE`: Reconstructed artifact timeline shown as a compact evidence table with row details.
- `Activity Matrix`: Shows timeline-relevant event counts by layer and event type.
- `Evidence Pie`: Shows the distribution of detections by forensic layer.
- `Relations`: Shows which artifacts came from which forensic layers.
- `Abort`: Stops the active analysis process without closing the application.

## Interface notes

- `From date` and `To date` filter the `TIMELINE` tab and `Activity Matrix` only. They do not change the forensic scan.
- The timeline is intentionally built from `System` and `Application` artifact timestamps only.
- `Created` and `Accessed` appear only when the tool can extract artifact-level timestamps from the evidence itself. It does not use the uploaded report file timestamp as a substitute.
- `Network`, `Transport`, and `Memory` detections do not drive the timeline because uploaded report-file times can be misleading.
- Selecting a row in any forensic layer tab shows the artifact path, evidence match, message, and timestamps in a dedicated details panel.
- Selecting a timeline row shows the corresponding artifact path, evidence match, and timestamp bundle.
- `Evidence Pie` is based on the number of detections per layer in the current case.
- `Activity Matrix` summarizes how many `Modified`, `Created`, and `Accessed` events were reconstructed per layer.
- `Relations` maps each detected artifact to the layer that produced it.

## Running from source

1. Create and activate a virtual environment.
2. Install dependencies.
3. Launch the GUI.

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python gui.py
```

## Building the EXE

The repo includes PyInstaller packaging files.

Build the EXE:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_exe.ps1
```

Build a portable release zip:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_release.ps1
```

Build a Windows installer:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_installer.ps1
```

Installer prerequisites:

- Inno Setup 6
- Optional: `signtool.exe` plus a valid code-signing certificate if you want a signed installer

Output locations:

- EXE: `dist\TorTraceAnalyzer.exe`
- Portable release zip: `release\TorTraceAnalyzer_Portable_<date>.zip`
- Installer: `release\TorTraceAnalyzer_Setup_<version>.exe`

## EXE portability notes

The packaged EXE has been hardened for use on other Windows systems:

- runtime temp/cache folders are redirected to safe writable locations,
- case data is stored under `%LOCALAPPDATA%\TorTraceAnalyzer`,
- report/temp graph paths do not depend on the launch directory,
- PCAP parsing is bundled for offline `.pcap` and `.pcapng` processing,
- the app no longer requires the source code beside the EXE.

## Installer and signing

- A full Windows installer is now included through Inno Setup.
- The installer build is signing-ready.
- The installer script auto-detects Inno Setup and searches common Windows SDK locations for `signtool.exe`.
- Actual code signing still requires your own certificate and `signtool.exe`.
- Signing instructions are available in `docs/CODE_SIGNING.md`.

If the EXE or installer is unsigned, Windows SmartScreen may show a warning. If needed, click `More info` and then `Run anyway`.

## Repository layout

```text
assets/                 icons, logo, screenshot
hooks/                  PyInstaller runtime hook
installer/              Inno Setup installer definition
scripts/                EXE and release build scripts
samples/                small demo evidence files
app_paths.py            app-safe resource and writable path helpers
gui.py                  desktop interface
main.py                 orchestration pipeline
file_parser.py          evidence parsing and classification
*_analysis.py           per-layer analyzers
pcap_transport_analysis.py  packet capture analysis
artifact_correlation.py correlation logic
risk_scoring.py         FCI scoring
timeline_reconstruction.py timeline builder
report_generator.py     report exports
TorTraceAnalyzer.spec   PyInstaller spec for the Windows EXE
```

## Validation completed

Before preparing the current release candidate, the project was checked for:

- successful Python compilation of core modules,
- successful module imports,
- end-to-end smoke testing of the analysis pipeline,
- `.pcap` and `.pcapng` routing,
- successful PyInstaller EXE build,
- packaged EXE startup validation.

## Dashboard preview

![Dashboard](assets/screenshot.png)

## Disclaimer

This project is intended for authorized forensic, educational, and research use. Always ensure that you have legal authority to analyze the evidence being processed.

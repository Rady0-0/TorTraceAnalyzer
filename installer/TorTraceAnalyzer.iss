#define MyAppName "TorTraceAnalyzer"
#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#ifndef RepoRoot
  #define RepoRoot ".."
#endif

[Setup]
AppId={{D7B9E246-0A8D-46C5-B237-9D4F0BCAB53D}
AppName={#MyAppName}
AppVersion={#AppVersion}
AppPublisher=TorTraceAnalyzer Project
AppPublisherURL=https://github.com/Rady0-0/TorTraceAnalyzer
AppSupportURL=https://github.com/Rady0-0/TorTraceAnalyzer/issues
DefaultDirName={autopf}\TorTraceAnalyzer
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
AllowNoIcons=yes
OutputDir={#RepoRoot}\release
OutputBaseFilename=TorTraceAnalyzer_Setup_{#AppVersion}
SetupIconFile={#RepoRoot}\assets\tortrace_icon.ico
WizardStyle=modern
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
UninstallDisplayIcon={app}\TorTraceAnalyzer.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
Source: "{#RepoRoot}\dist\TorTraceAnalyzer.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#RepoRoot}\docs\QUICK_START.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#RepoRoot}\samples\*"; DestDir: "{app}\sample_inputs"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\TorTraceAnalyzer"; Filename: "{app}\TorTraceAnalyzer.exe"; WorkingDir: "{app}"
Name: "{group}\Quick Start"; Filename: "{app}\QUICK_START.txt"
Name: "{group}\Sample Inputs"; Filename: "{app}\sample_inputs"
Name: "{group}\Uninstall TorTraceAnalyzer"; Filename: "{uninstallexe}"
Name: "{autodesktop}\TorTraceAnalyzer"; Filename: "{app}\TorTraceAnalyzer.exe"; Tasks: desktopicon; WorkingDir: "{app}"

[Run]
Filename: "{app}\TorTraceAnalyzer.exe"; Description: "Launch TorTraceAnalyzer"; Flags: nowait postinstall skipifsilent

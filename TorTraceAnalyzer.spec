# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_data_files


datas = []
datas += collect_data_files("customtkinter")
datas += collect_data_files("scapy")
datas += [
    ("assets\\tortrace_icon.ico", "assets"),
    ("assets\\tortrace_logo.png", "assets"),
]

hiddenimports = [
    "pcap_transport_analysis",
    "matplotlib.backends.backend_tkagg",
    "scapy.layers.inet",
    "scapy.utils",
]

excludes = [
    "matplotlib.tests",
    "pytest",
    "_pytest",
    "IPython",
    "PyQt5",
    "PyQt6",
    "PySide2",
    "PySide6",
    "wx",
    "gi",
]


a = Analysis(
    ["gui.py"],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=["hooks\\runtime_env.py"],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="TorTraceAnalyzer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    runtime_tmpdir=None,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="assets\\tortrace_icon.ico",
)

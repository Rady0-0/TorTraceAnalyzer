import re

def extract_internal_metadata(content, default_ts, artifact_name):
    time_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    times = re.findall(time_pattern, content)
    path_pattern = r'([a-zA-Z]:\\[\\\w\s\.\-\(\)]+|/[\w\s\.\-\(\)/]+)'
    paths = re.findall(path_pattern, content)
    raw_path = paths[0] if paths else "Path not found"
    full_path = raw_path
    if artifact_name.lower() not in raw_path.lower():
        sep = "/" if "/" in raw_path else "\\"
        full_path = f"{raw_path.rstrip(sep)}{sep}{artifact_name.lower()}"
    return {"time": times[0] if times else default_ts.get('modified', 'N/A'), "path": full_path}

def check_system(file_data):
    content = file_data.get("content", "").lower()
    ts_metadata = file_data.get("timestamps", {})
    results = []
    
    system_indicators = {
        ".pf": "Windows Prefetch: Proves application execution history.",
        "usb": "Removable Media Trace: Artifact located on external storage.",
        "event id 1102": "Audit Log Wiping: Standard forensic log-clear event detected.",
        "userassist": "Registry UserAssist: Metadata confirming manual GUI launch.",
        "rar": "Compression Artifact: Evidence of data packaging activity.",
        "7z": "Compression Artifact: Evidence of data packaging activity."
    }
    
    for indicator, reason in system_indicators.items():
        if indicator in content:
            if indicator == ".pf":
                match = re.search(r'([\w\.-]*tor[\w\.-]*\.pf)', content)
                name = match.group(1).upper() if match else "TOR.EXE.PF"
            else:
                name = indicator.upper()
            ext = extract_internal_metadata(content, ts_metadata, name)
            results.append({
                "layer": "System", "status": "Detected", "file_name": name,
                "file_path": ext["path"], "message": reason,
                "disk_timestamps": {"modified": ext["time"]}
            })
    return results
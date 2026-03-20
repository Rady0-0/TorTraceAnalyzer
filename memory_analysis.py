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

def check_memory(file_data):
    content = file_data.get("content", "").lower()
    ts_metadata = file_data.get("timestamps", {})
    results = []
    mem_artifacts = {
        "tor.exe": "Core Tor Onion Routing process detected.",
        "obfs4proxy.exe": "Tor Bridge (obfs4) detected; bypass attempt identified.",
        "tor-browser.exe": "Tor Browser parent process identified."
    }
    for artifact, reason in mem_artifacts.items():
        if artifact in content:
            ext = extract_internal_metadata(content, ts_metadata, artifact)
            results.append({
                "layer": "Memory", "status": "Detected", "file_name": artifact.upper(),
                "file_path": ext["path"], "message": reason,
                "disk_timestamps": {"modified": ext["time"]} 
            })
    return results
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

def check_network(file_data):
    content = file_data.get("content", "").lower()
    ts_metadata = file_data.get("timestamps", {})
    results = []
    indicators = {
        "9050": "Tor SOCKS Port (Default).",
        "9150": "Tor Browser Bundle Port.",
        "tap-windows": "VPN Virtual Adapter: Confirms Scenario 2/3 (VPN+Tor).",
        "tun0": "Active VPN Tunnel interface identified.",
        "ip change": "Network Log: Detected IP address shift consistent with Tor/VPN."
    }
    for key, reason in indicators.items():
        if key in content:
            ext = extract_internal_metadata(content, ts_metadata, key.upper())
            results.append({
                "layer": "Network", "status": "Detected", "file_name": key.upper(),
                "file_path": ext["path"], "message": reason,
                "disk_timestamps": {"modified": ext["time"]}
            })
    return results
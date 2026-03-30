import re

def extract_internal_metadata(content, default_ts, artifact_name):
    idx = content.find(artifact_name.lower())
    if idx == -1:
        return {"time": "N/A", "path": "Path not found"}
    
    window = content[max(0, idx-500): min(len(content), idx+500)]
    
    time_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    times = re.findall(time_pattern, window)
    
    path_pattern = r'([a-zA-Z]:\\[\\\w\s\.\-\(\)]+|/[\w\s\.\-\(\)/]+)'
    paths = re.findall(path_pattern, window)
    
    raw_path = "Path not found"

    for p in paths:
        if artifact_name.lower() in p.lower():
            raw_path = p
            break

# fallback
    if raw_path == "Path not found" and paths:
        raw_path = paths[0]
    
    return {
        "time": times[0] if times else default_ts.get('modified', 'N/A'),
        "path": raw_path
    }


# 🔥 STRICT EXECUTABLE LIST
VALID_TOR_EXECUTABLES = [
    "tor.exe",
    "firefox.exe",
    "torbrowser.exe"
]


# 🔥 STRICT PREFETCH VALIDATION (MAIN FIX)
def is_valid_tor_prefetch(pf_name):
    pf_name = pf_name.lower()

    # Example: firefox.exe-XXXX.pf
    for exe in VALID_TOR_EXECUTABLES:
        if pf_name.startswith(exe + "-"):
            return True

    return False


# 🔥 PATH VALIDATION (IMPORTANT)
def is_valid_prefetch_path(path):
    path = path.lower()

    if "windows/prefetch" not in path:
        return False

    if "slack" in path or "layout.ini" in path:
        return False

    return True


def check_system(file_data):
    content = file_data.get("content", "").lower()
    ts_metadata = file_data.get("timestamps", {})
    results = []

    seen = set()

    # ============================================
    # 1. STRICT PREFETCH DETECTION
    # ============================================
    pf_matches = re.findall(r'\b[\w\.-]+\.pf\b', content)

    for pf in pf_matches:

        pf_lower = pf.lower()

        # ✅ FIX 1: STRICT MATCH
        if not is_valid_tor_prefetch(pf_lower):
            continue

        # ✅ FIX 2: REMOVE DUPLICATES
        if pf_lower in seen:
            continue
        seen.add(pf_lower)

        ext = extract_internal_metadata(content, ts_metadata, pf)

        # ✅ FIX 3: VALID PATH ONLY
        if not is_valid_prefetch_path(ext["path"]):
            continue

        results.append({
            "layer": "System",
            "status": "Detected",
            "file_name": "TOR EXECUTION (PREFETCH)",
            "file_path": ext["path"],
            "message": "Confirmed execution of Tor-related executable via Prefetch.",
            "evidence_match": pf.upper(),
            "disk_timestamps": {
                "modified": ext["time"],
                "created": ts_metadata.get("created", "N/A"),
                "accessed": ts_metadata.get("accessed", "N/A")
            }
        })

    # ============================================
    # 2. USB DETECTION
    # ============================================
    if "usbstor" in content:
        ext = extract_internal_metadata(content, ts_metadata, "usbstor")

        results.append({
            "layer": "System",
            "status": "Detected",
            "file_name": "REMOVABLE STORAGE",
            "file_path": ext["path"],
            "message": "USB device usage detected (possible portable Tor usage).",
            "evidence_match": "USBSTOR",
            "disk_timestamps": {
                "modified": ext["time"],
                "created": ts_metadata.get("created", "N/A"),
                "accessed": ts_metadata.get("accessed", "N/A")
            }
        })

    # ============================================
    # 3. EVENT LOG CLEAR
    # ============================================
    if "1102" in content and "cleared" in content:
        ext = extract_internal_metadata(content, ts_metadata, "1102")

        results.append({
            "layer": "System",
            "status": "Detected",
            "file_name": "EVENT LOG CLEARED",
            "file_path": ext["path"],
            "message": "Security logs were cleared (anti-forensics behavior).",
            "evidence_match": "Event ID 1102",
            "disk_timestamps": {
                "modified": ext["time"],
                "created": ts_metadata.get("created", "N/A"),
                "accessed": ts_metadata.get("accessed", "N/A")
            }
        })

    return results
import re


def _build_timestamp_bundle(time_values, default_ts):
    cleaned = [value.strip() for value in time_values if value and value != "0000-00-00 00:00:00"]
    return {
        "modified": cleaned[0] if len(cleaned) > 0 else default_ts.get("modified", "N/A"),
        "accessed": cleaned[1] if len(cleaned) > 1 else "N/A",
        "created": cleaned[2] if len(cleaned) > 2 else "N/A",
    }


def extract_internal_metadata(content, default_ts, artifact_name):
    time_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    path_pattern = r'([a-zA-Z]:\\[\\\w \.\-\(\)]+|/[\w \.\-\(\)/]+)'
    artifact_lower = artifact_name.lower()

    for line in content.splitlines():
        if artifact_lower not in line.lower():
            continue

        times = re.findall(time_pattern, line)
        paths = re.findall(path_pattern, line)
        raw_path = "Path not found"
        for p in paths:
            if artifact_lower in p.lower():
                raw_path = p
                break
        if raw_path == "Path not found" and paths:
            raw_path = paths[0]
        return {
            "timestamps": _build_timestamp_bundle(times, default_ts),
            "path": raw_path
        }

    idx = content.find(artifact_lower)
    if idx == -1:
        return {
            "timestamps": _build_timestamp_bundle([], default_ts),
            "path": "Path not found",
        }

    window_start = max(0, idx-500)
    window = content[window_start: min(len(content), idx+500)]
    times = list(re.finditer(time_pattern, window))
    paths = re.findall(path_pattern, window)

    raw_path = "Path not found"

    for p in paths:
        if artifact_lower in p.lower():
            raw_path = p
            break

    # fallback
    if raw_path == "Path not found" and paths:
        raw_path = paths[0]

    extracted_times = [match.group(1) for match in times]
    
    return {
        "timestamps": _build_timestamp_bundle(extracted_times, default_ts),
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
    path = path.lower().replace("\\", "/")

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
            "disk_timestamps": ext["timestamps"],
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
            "disk_timestamps": ext["timestamps"],
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
            "disk_timestamps": ext["timestamps"],
        })

    return results

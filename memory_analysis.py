import re

def extract_internal_metadata(content, default_ts, artifact_name):
    idx = content.find(artifact_name.lower())
    if idx == -1:
        return {"time": "Live Analysis", "path": "Memory Segment"}

    window = content[max(0, idx-500): min(len(content), idx+500)]

    time_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    times = re.findall(time_pattern, window)

    path_pattern = r'[A-Za-z]:\\[^\s]+'
    paths = re.findall(path_pattern, window)

    return {
        "time": times[0] if times else default_ts.get("modified", "Live"),
        "path": paths[0] if paths else "Memory Segment"
    }


def check_memory(file_data):
    content = file_data.get("content", "").lower()
    ts_metadata = file_data.get("timestamps", {})
    results = []

    # ============================================
    # 1. STRONG INDICATORS (HIGH CONFIDENCE)
    # ============================================
    if re.search(r"\btor\.exe\b", content):
        results.append({
            "layer": "Memory",
            "status": "Detected",
            "file_name": "TOR PROCESS",
            "file_path": "Memory Process",
            "message": "Tor process detected in memory",
            "evidence_match": "tor.exe",
            "disk_timestamps": ts_metadata
        })

    if re.search(r"\bfirefox\.exe\b", content) and re.search(r"\btor\b", content):
        results.append({
            "layer": "Memory",
            "status": "Suspicious",
            "file_name": "TOR BROWSER",
            "file_path": "Memory Process",
            "message": "Tor browser (Firefox-based) activity suspected",
            "evidence_match": "firefox.exe + tor reference",
            "disk_timestamps": ts_metadata
        })

    # ============================================
    # 2. MEDIUM INDICATORS
    # ============================================
    if re.search(r"\btorrc\b", content):
        results.append({
            "layer": "Memory",
            "status": "Detected",
            "file_name": "TOR CONFIG",
            "file_path": "Memory Artifact",
            "message": "Tor configuration reference found in memory",
            "evidence_match": "torrc",
            "disk_timestamps": ts_metadata
        })

    if re.search(r"\.onion\b", content):
        results.append({
            "layer": "Memory",
            "status": "Detected",
            "file_name": "ONION DOMAIN",
            "file_path": "Memory Artifact",
            "message": "Tor hidden service reference found",
            "evidence_match": ".onion",
            "disk_timestamps": ts_metadata
        })

    # ============================================
    # 3. WEAK / INDIRECT INDICATORS (FIXED 🔥)
    # ============================================

    # STRICT WORD MATCH (prevents sTORage issue)
    tor_mentions = len(re.findall(r"\btor\b", content, re.IGNORECASE))

    # Additional Tor-related patterns
    tor_related = re.findall(
        r"\btor\.(exe|dll)\b|\btorrc\b|\bonion\b",
        content,
        re.IGNORECASE
    )

    if tor_mentions > 2 or len(tor_related) > 0:
        results.append({
            "layer": "Memory",
            "status": "Suspicious",
            "file_name": "POSSIBLE TOR TRACE",
            "file_path": "Memory Analysis",
            "message": "Validated Tor-related patterns found (false positives filtered)",
            "evidence_match": f"Tor mentions: {tor_mentions}, Related hits: {len(tor_related)}",
            "disk_timestamps": ts_metadata
        })

    # ============================================
    # 4. COMMAND LINE DETECTION
    # ============================================
    if "--socksport" in content or "--controlport" in content:
        results.append({
            "layer": "Memory",
            "status": "Detected",
            "file_name": "TOR COMMAND",
            "file_path": "Process Arguments",
            "message": "Tor command-line arguments detected",
            "evidence_match": "Tor execution parameters",
            "disk_timestamps": ts_metadata
        })

    return results
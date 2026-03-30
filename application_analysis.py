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
    
    raw_path = paths[0] if paths else "Path not found"

    return {
        "time": times[0] if times else default_ts.get('modified', 'N/A'),
        "path": raw_path
    }


def check_application(file_data):
    content = file_data.get("content", "").lower()
    ts_metadata = file_data.get("timestamps", {})
    results = []

    # ============================================
    # STRICT TOR APPLICATION ARTIFACTS
    # ============================================
    app_indicators = {
        "places.sqlite": "History Database: Contains Tor browsing activity.",
        "cookies.sqlite": "Session Data: Evidence of Tor browsing sessions.",
        "noscript": "Security Policy: Indicates Tor Browser hardened mode.",
        "torrc": "Core Config: Defines Tor network behavior and routing."
    }

    # Strong Tor path indicators
    TOR_PATH_HINTS = ["tor", "tor browser", "onion"]

    # Known system noise paths
    EXCLUDED_PATHS = ["windows", "microsoft", "onesettings"]

    for artifact, reason in app_indicators.items():

        # FAST FILTER
        if artifact not in content:
            continue

        pattern = rf"\b{re.escape(artifact)}\b"

        if re.search(pattern, content):
            ext = extract_internal_metadata(content, ts_metadata, artifact)

            path_lower = ext["path"].lower()

            # ❌ Skip system noise
            if any(excl in path_lower for excl in EXCLUDED_PATHS):
                continue

            # 🔴 STRICT VALIDATION (IMPORTANT FIX)
            if not any(hint in path_lower for hint in TOR_PATH_HINTS):
                continue

            match = re.search(rf"\b[\w\.-]*{artifact}[\w\.-]*\b", content)
            evidence_match = match.group(0).upper() if match else artifact.upper()

            results.append({
                "layer": "Application",
                "status": "Detected",
                "file_name": artifact.upper(),
                "file_path": ext["path"],
                "message": reason,
                "evidence_match": f"Application Anchor: {evidence_match}",
                "disk_timestamps": {
                    "modified": ext["time"],
                    "created": ts_metadata.get("created", "N/A"),
                    "accessed": ts_metadata.get("accessed", "N/A")
                }
            })

    return results
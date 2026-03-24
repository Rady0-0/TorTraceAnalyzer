import re

def extract_internal_metadata(content, default_ts, artifact_name):
    """
    Step 2: Contextual Windowing. 
    SPEED FIX: Widened window to 500 to catch paths in complex Autopsy tables.
    """
    idx = content.find(artifact_name.lower())
    if idx == -1: return {"time": "N/A", "path": "Path not found"}
    
    # Large window to handle long forensic report rows
    window = content[max(0, idx-500) : min(len(content), idx+500)]
    
    time_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    times = re.findall(time_pattern, window)
    
    path_pattern = r'([a-zA-Z]:\\[\\\w\s\.\-\(\)]+|/[\w\s\.\-\(\)/]+)'
    paths = re.findall(path_pattern, window)
    
    raw_path = paths[0] if paths else "Path not found"
    full_path = raw_path
    
    if artifact_name.lower() not in raw_path.lower() and raw_path != "Path not found":
        sep = "/" if "/" in raw_path else "\\"
        full_path = f"{raw_path.rstrip(sep)}{sep}{artifact_name.lower()}"
    
    return {"time": times[0] if times else default_ts.get('modified', 'N/A'), "path": full_path}

def check_application(file_data):
    content = file_data.get("content", "").lower()
    ts_metadata = file_data.get("timestamps", {})
    results = []
    
    # SPEED OPTIMIZATION: Indicators now include 'Quick Keywords'
    # This prevents the Regex from scanning the entire file if the word isn't there.
    app_indicators = {
        "settings.json": ("Browser Config: Proves Tor was customized. Contains security levels.", ["settings", ".json"]),
        "places.sqlite": ("History Database: Forensic goldmine containing browsing history.", ["places", ".sqlite"]),
        "cookies.sqlite": ("Session Data: Evidence of active website logins and sessions.", ["cookies", ".sqlite"]),
        "noscript": ("Security Policy: Proves usage of Tor's high-security mode.", ["noscript"]),
        "torrc": ("Core Config: Primary file defining Tor's bridge and node behavior.", ["torrc"])
    }
    
    for artifact, (reason, keywords) in app_indicators.items():
        # FAST PRE-FILTER: Skip the file if keywords aren't present
        if not any(k in content for k in keywords):
            continue

        pattern = rf"\b{re.escape(artifact)}\b"
        
        if re.search(pattern, content):
            ext = extract_internal_metadata(content, ts_metadata, artifact)
            
            # --- PATH GUARD: Contextual Validation ---
            # Filters out Windows/Edge/Chrome 'settings.json' or 'cookies'
            if artifact in ["settings.json", "cookies.sqlite"]:
                # If the path doesn't mention Tor, Browser, or Onion, it's a False Positive
                if not any(x in ext["path"].lower() for x in ["tor", "browser", "onion"]):
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
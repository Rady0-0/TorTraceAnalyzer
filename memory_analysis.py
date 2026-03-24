import re

def extract_internal_metadata(content, default_ts, artifact_name):
    """
    Step 2: Contextual Windowing. 
    In memory forensics, there are rarely 'paths', so we capture the surrounding string
    to show the 'Memory Offset' context.
    """
    idx = content.find(artifact_name.lower())
    window = content[max(0, idx-150) : min(len(content), idx+150)]
    
    # We look for memory-like strings or process hints
    path_pattern = r'([a-zA-Z]:\\[\\\w\s\.\-\(\)]+|/[\w\s\.\-\(\)/]+)'
    paths = re.findall(path_pattern, window)
    
    raw_path = paths[0] if paths else f"Memory Segment [Offset: {hex(idx)}]"
    
    return {"time": default_ts.get('modified', 'Live Capture'), "path": raw_path}

def check_memory(file_data):
    content = file_data.get("content", "").lower()
    ts_metadata = file_data.get("timestamps", {})
    results = []
    
    # --- FORENSIC TOOL EXCLUSION ---
    # Prevents 'Self-Detection' if the capture tool or analyzer is in the strings.
    forensic_tools_exclusion = ["volatility", "dumpit", "magnet", "belkasoft", "memdump"]
    
    # Requirement 4: Forensic Justifications
    # Using strict word boundaries (\b) to avoid 'accelerator' matching 'tor'.
    memory_indicators = {
        r"\btor\.exe\b": "Active Process: Core Tor service identified in volatile memory.",
        r"\bfirefox\.exe\b": "Browser Core: The modified Firefox binary used by Tor is active.",
        r"onion-location": "Live Header: Evidence of an active connection to a .onion hidden service.",
        r"torrc": "Memory Config: Tor configuration strings identified in a process memory heap."
    }

    for pattern, reason in memory_indicators.items():
        if re.search(pattern, content):
            # Extract the actual match
            match = re.search(pattern, content)
            found_text = match.group(0).upper()
            
            ext = extract_internal_metadata(content, ts_metadata, found_text)
            
            # --- NOISE FILTERING ---
            if any(tool in ext["path"].lower() for tool in forensic_tools_exclusion):
                continue

            results.append({
                "layer": "Memory", 
                "status": "Detected", 
                "file_name": found_text,
                "file_path": ext["path"], 
                "message": reason,
                "evidence_match": f"Memory String: {found_text}",
                "disk_timestamps": {
                    "modified": ext["time"],
                    "created": "Volatile",
                    "accessed": "Live"
                }
            })
            
    return results
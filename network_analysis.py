import re

def extract_internal_metadata(content, default_ts, artifact_name):
    """
    Step 2: Contextual Windowing. 
    SPEED FIX: Widened window to 500 to catch IP addresses in wide CSV rows.
    """
    idx = content.find(artifact_name.lower())
    if idx == -1: return {"time": "N/A", "path": "Network Log Segment"}
    
    # Large window to handle long network log lines
    window = content[max(0, idx-500) : min(len(content), idx+500)]
    
    time_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    times = re.findall(time_pattern, window)
    
    path_pattern = r'([a-zA-Z]:\\[\\\w\s\.\-\(\)]+|/[\w\s\.\-\(\)/]+)'
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    
    paths = re.findall(path_pattern, window)
    ips = re.findall(ip_pattern, window)
    
    # If no disk path, use the IP as the forensic location
    location = paths[0] if paths else (f"Packet Stream [IP: {ips[0]}]" if ips else "Network Log Segment")
    
    return {"time": times[0] if times else default_ts.get('modified', 'N/A'), "path": location}

def check_network(file_data):
    content = file_data.get("content", "").lower()
    ts_metadata = file_data.get("timestamps", {})
    results = []
    
    forensic_tools_exclusion = ["wireshark", "tshark", "pcap", "autopsy", "tcpdump"]
    
    # SPEED OPTIMIZATION: Indicators now include 'Quick Keywords'
    indicators = {
        "9050": ("Tor SOCKS: Default proxy traffic detected.", ["9050"]),
        "9150": ("TBB Port: Tor Browser specific communication identified.", ["9150"]),
        "tun0": ("Active Tunnel: A virtual VPN interface was active.", ["tun0"]),
        "wireguard": ("VPN Traffic: Wireguard protocol signatures found.", ["wireguard"]),
        ".onion": ("Hidden Service: Request to a Tor-specific domain.", [".onion"])
    }
    
    for key, (reason, keywords) in indicators.items():
        # FAST PRE-FILTER: Skip the heavy Regex if keywords aren't even in the file
        if not any(k in content for k in keywords):
            continue

        # Port-Aware Regex (prevents hash collisions)
        if key.isdigit():
            pattern = rf"(?::|\s|^){re.escape(key)}(?!\d)"
        else:
            pattern = rf"\b{re.escape(key)}\b"
        
        if re.search(pattern, content):
            ext = extract_internal_metadata(content, ts_metadata, key)
            
            # --- THE LAYER GUARD ---
            # If the hit is in a 'Prefetch' file, the Network layer ignores it.
            if "prefetch" in ext["path"].lower() or ".pf" in ext["path"].lower():
                continue
            
            # Tool Exclusion
            if any(tool in ext["path"].lower() for tool in forensic_tools_exclusion if "/" in ext["path"] or "\\" in ext["path"]):
                continue

            # Capture exact match for the UI (e.g., ':9150')
            match = re.search(rf"[\w\.\:]*{key}[\w\.\:]*", content)
            evidence_match = match.group(0).upper() if match else key.upper()
            
            results.append({
                "layer": "Network", 
                "status": "Detected", 
                "file_name": f"PORT {key}" if key.isdigit() else key.upper(),
                "file_path": ext["path"], 
                "message": reason,
                "evidence_match": f"Network Anchor: {evidence_match}",
                "disk_timestamps": {
                    "modified": ext["time"],
                    "created": ts_metadata.get("created", "N/A"),
                    "accessed": ts_metadata.get("accessed", "N/A")
                }
            })
    return results
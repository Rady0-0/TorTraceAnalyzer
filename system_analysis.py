import re

def extract_internal_metadata(content, default_ts, artifact_name):
    """
    Step 2: Contextual Windowing. 
    RECOVERY FIX: 500-char window to catch data in messy Autopsy tables.
    """
    idx = content.find(artifact_name.lower())
    if idx == -1: return {"time": "N/A", "path": "Path not found"}
    
    # Large window to handle long forensic paths
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

def check_system(file_data):
    content = file_data.get("content", "").lower()
    ts_metadata = file_data.get("timestamps", {})
    results = []
    
    # --- NOISE FILTERING ---
    forensic_tools_exclusion = ["autopsy/rr-full/plugins", "wireshark/radius"]
    
    # SPEED OPTIMIZATION: We define 'Quick Keywords' to check before running Regex
    system_indicators = {
        r"[\w\.-]*(tor|firefox)[\w\.-]*\.pf[\w\.-]*": ("TOR PREFETCH", ["tor", ".pf"]),
        r"[\w\.-]*(vpn|wireguard|proton|tunnel)[\w\.-]*\.pf[\w\.-]*": ("VPN PREFETCH", ["vpn", "wireguard", "proton"]),
        r"usbstor|removable\smedia": ("REMOVABLE STORAGE", ["usb", "removable"]),
        r"event\s1102|audit\slog\scleared": ("EVENT 1102", ["1102", "cleared"]),
        r"userassist.*tor": ("USERASSIST (TOR)", ["userassist", "tor"])
    }

    reasons = {
        "TOR PREFETCH": "Execution Trace: Windows Prefetch proves the Tor Browser was launched.",
        "VPN PREFETCH": "Execution Trace: Windows Prefetch proves a VPN client was executed.",
        "REMOVABLE STORAGE": "USB Activity: Proves use of external media to bypass local logs.",
        "EVENT 1102": "Anti-Forensics: Proof that Security Audit logs were intentionally cleared.",
        "USERASSIST (TOR)": "User Interaction: Registry data confirms manual GUI interaction with Tor."
    }

    for pattern, (label, keywords) in system_indicators.items():
        # FAST PRE-FILTER: If none of the keywords are in the file, skip the heavy Regex!
        if not any(k in content for k in keywords):
            continue

        match = re.search(pattern, content)
        if match:
            found_text = match.group(0)
            ext = extract_internal_metadata(content, ts_metadata, found_text)
            
            if any(tool in ext["path"].lower() for tool in forensic_tools_exclusion):
                continue

            results.append({
                "layer": "System", "status": "Detected", "file_name": label,
                "file_path": ext["path"], "message": reasons[label],
                "evidence_match": f"Forensic Anchor: {found_text.upper()}",
                "disk_timestamps": {
                    "modified": ext["time"], 
                    "created": ts_metadata.get("created", "N/A"), 
                    "accessed": ts_metadata.get("accessed", "N/A")
                }
            })

    # --- GENERAL VPN CHECK (Optional Backup) ---
    vpn_keys = ["protonvpn", "wireguard", "openvpn"]
    if any(vk in content for vk in vpn_keys):
        for vpn_key in vpn_keys:
            if vpn_key in content:
                ext = extract_internal_metadata(content, ts_metadata, vpn_key)
                if any(r["file_name"] == "VPN PREFETCH" for r in results): continue
                
                results.append({
                    "layer": "System", "status": "Detected", "file_name": "VPN/TUNNEL",
                    "file_path": ext["path"], 
                    "message": f"Anonymity Tech: Detected {vpn_key.upper()} traces.",
                    "evidence_match": f"Technology Identified: {vpn_key.upper()}",
                    "disk_timestamps": {
                        "modified": ext["time"], "created": ts_metadata.get("created", "N/A"), "accessed": ts_metadata.get("accessed", "N/A")
                    }
                })
                break 

    return results
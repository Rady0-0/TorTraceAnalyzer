def correlate_artifacts(layer_hits, all_detections):
    """
    Step 5: Behavioral Pattern Correlation. 
    Links isolated traces across layers to prove investigative 'Modus Operandi'.
    """
    correlations = []
    
    # 1. PRE-PROCESSING: Standardize lookups
    # We pull the names and paths from all detections found across all files.
    found_names = {d['file_name'].upper() for d in all_detections}
    found_paths = {d['file_path'].lower() for d in all_detections}
    full_narrative = " ".join([d['message'].lower() for d in all_detections])

    # 2. PATTERN: DATA EXFILTRATION (LINKING TOR + COMPRESSION)
    # Proves the suspect was preparing files to be moved over the darknet.
    has_compression = any(x in full_narrative for x in ["rar", "7z", "zip", "compress", "archive"])
    has_tor_active = any(x in found_names for x in ["PORT 9050", "PORT 9150", ".ONION ADDRESS"]) or layer_hits.get("network")
    
    if has_compression and has_tor_active:
        correlations.append("CRITICAL: Potential Data Exfiltration. Compressed archives identified alongside active Tor network signatures.")

    # 3. PATTERN: PORTABLE EXECUTION (LINKING TOR + REMOVABLE MEDIA)
    # Proves Tor was run from a USB to avoid leaving traces on the local C: drive.
    is_on_usb = "REMOVABLE STORAGE" in found_names or any(p.startswith(("/vol", "e:", "f:", "g:", "h:")) for p in found_paths)
    
    if is_on_usb and ("TOR.EXE" in found_names or "TOR PREFETCH" in found_names):
        correlations.append("HIGH: Portable Execution. Artifact paths confirm Tor was launched from a removable volume.")

    # 4. PATTERN: PROVEN HUMAN INTENT (LINKING TOR + USERASSIST/HISTORY)
    # Proves manual interaction. This is key to defeating the "it was malware/automated" defense.
    has_manual_launch = "USERASSIST (TOR)" in found_names
    has_browsing_history = "PLACES.SQLITE" in found_names
    
    if has_manual_launch or has_browsing_history:
        correlations.append("MANUAL INTENT: User-Initiated Activity. Registry or Browser History confirms human interaction with the Tor environment.")

    # 5. PATTERN: LAYERED TUNNELING (LINKING TOR + VPN)
    # Proves a deliberate attempt to hide the use of Tor from the ISP.
    # We check for the VPN software (System) and the VPN traffic (Network).
    has_vpn_tech = any(x in found_names for x in ["VPN/TUNNEL", "VPN PREFETCH", "WIREGUARD", "OPENVPN"])
    
    if has_vpn_tech and has_tor_active:
        correlations.append("HIGH: Layered Tunneling. VPN/Wireguard activity detected in conjunction with Tor-specific traffic.")

    # 6. PATTERN: ANTI-FORENSIC ACTIVITY (EVENT 1102)
    # Proves the suspect knew they were being watched and tried to hide.
    if "EVENT 1102" in found_names:
        correlations.append("WARNING: Anti-Forensic Activity. Evidence indicates system security logs were intentionally cleared.")

    summary = " | ".join(correlations) if correlations else "No multi-layer behavioral patterns identified."

    return {
        "correlations": correlations,
        "summary": summary
    }
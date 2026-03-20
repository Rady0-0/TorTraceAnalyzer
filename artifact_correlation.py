def correlate_artifacts(layer_hits, all_detections):
    """
    Identifies high-level behavioral patterns by correlating traces 
    across memory, system, network, and application layers.
    """
    correlations = []
    
    # Data mining the combined narrative of all detections
    full_narrative = " ".join([d['message'].lower() for d in all_detections])
    full_paths = " ".join([d['file_name'].lower() + d['file_path'].lower() for d in all_detections])

    # 1. PATTERN: POTENTIAL DATA EXFILTRATION
    has_compression = any(x in full_narrative for x in ["rar", "7z", "zip", "compress"])
    if layer_hits.get("network") and layer_hits.get("memory") and has_compression:
        correlations.append("CRITICAL: Data Exfiltration Pattern. Evidence of file compression identified alongside active Tor session.")

    # 2. PATTERN: ANONYMOUS TUNNELING
    has_vpn = any(x in full_narrative for x in ["tap", "tun", "vpn", "tunnel", "wireguard", "openvpn"])
    if has_vpn and layer_hits.get("network"):
        correlations.append("HIGH: Layered Tunneling. VPN/Tunneling interface detected in conjunction with Tor network activity.")

    # 3. PATTERN: PORTABLE/REMOVABLE EXECUTION
    # Flags if Tor was run from a non-system partition or USB
    is_portable = any(x in full_narrative or x in full_paths for x in ["usb", "removable", "vol_"])
    if is_portable:
        correlations.append("WARNING: Portable Execution. Artifact paths indicate the application was launched from a removable or non-system volume.")

    # 4. PATTERN: ANTI-FORENSIC ACTIVITY
    if "cleared" in full_narrative or "1102" in full_narrative:
        correlations.append("WARNING: Anti-Forensic Trace Erasure. Evidence indicates system audit logs were intentionally cleared.")

    # 5. PATTERN: VOLATILE DATA CLEARING (REBOOT)
    if "shutdown" in full_narrative or "restart" in full_narrative:
        correlations.append("INFO: System State Change. A restart/shutdown event was recorded, potentially clearing volatile memory traces.")

    summary = " | ".join(correlations) if correlations else "No multi-layer behavioral patterns identified."

    return {
        "correlations": correlations,
        "summary": summary
    }
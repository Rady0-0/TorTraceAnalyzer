def _extract_name(detection):
    name = detection.get("file_name") or detection.get("artifact") or ""
    return str(name).upper()


def correlate_artifacts(layer_hits, all_detections):
    correlations = []
    names = [_extract_name(detection) for detection in all_detections]

    has_execution = any(
        "PREFETCH" in name or "TOR PROCESS" in name or "TOR EXECUTION" in name
        for name in names
    )
    has_direct_tor = any(
        any(port in name for port in ("PORT 9001", "PORT 9030", "PORT 9050", "PORT 9150"))
        or ".ONION" in name
        or "TOR COMMUNICATION CONFIRMED" in name
        for name in names
    )
    has_behavioral = any(
        "POSSIBLE TOR" in name or "TOR-LIKE" in name
        for name in names
    )
    has_vpn = any("VPN" in name for name in names)
    has_transport = any(
        "DATA FLOW" in name or "ENCRYPTED TRANSPORT" in name or "TCP DATA FLOW" in name
        for name in names
    )
    has_pcap_tor = any("TOR COMMUNICATION CONFIRMED" in name for name in names)
    has_pcap_behavior = any("TOR-LIKE MULTI-NODE TRAFFIC" in name for name in names)
    has_exfiltration = any("EXFILTRATION" in name for name in names)

    if has_execution:
        correlations.append("HIGH: Tor execution confirmed via system-level artifacts.")

    if has_direct_tor:
        correlations.append("CRITICAL: Direct Tor indicators detected (known ports or onion services).")

    if has_pcap_tor:
        correlations.append("CRITICAL: Packet-level analysis confirms Tor communication.")

    if has_behavioral and not has_direct_tor:
        correlations.append("HIGH: Tor-like network behavior observed.")

    if has_pcap_behavior:
        correlations.append("HIGH: Multi-node encrypted traffic pattern consistent with Tor routing.")

    if has_vpn and (has_execution or has_behavioral or has_pcap_tor):
        correlations.append("HIGH: Layered anonymization detected (VPN + Tor activity).")
    elif has_vpn:
        correlations.append("MEDIUM: VPN usage detected. Traffic may be concealed.")

    if has_transport:
        correlations.append("MEDIUM: Active transport-layer data transfer detected.")

    if has_execution and (has_transport or has_pcap_tor):
        correlations.append("CRITICAL: Data transfer likely occurred through Tor (execution + transport correlation).")
    elif has_behavioral and (has_transport or has_pcap_behavior):
        correlations.append("HIGH: Transport behavior aligns with Tor-like encrypted routing.")

    if has_exfiltration:
        correlations.append("CRITICAL: Potential data exfiltration detected.")

    active_layers = sum(bool(layer_hits.get(layer)) for layer in layer_hits)
    if active_layers >= 4:
        correlations.append("CRITICAL: Evidence spans multiple forensic layers.")
    elif active_layers >= 3:
        correlations.append("HIGH: Strong multi-layer forensic correlation.")
    elif active_layers == 2:
        correlations.append("MEDIUM: Limited cross-layer evidence.")

    if not correlations:
        correlations.append("LOW: No strong indicators of Tor usage detected.")

    return {
        "correlations": correlations,
        "summary": " | ".join(correlations),
    }

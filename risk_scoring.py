def _extract_name(detection):
    name = detection.get("file_name") or detection.get("artifact") or ""
    return str(name).upper()


def calculate_fci(layer_hits, all_detections):
    total_score = 0
    max_score = 100
    names = [_extract_name(detection) for detection in all_detections]
    application_hits = sum(
        1
        for name in names
        if any(indicator in name for indicator in ("PLACES.SQLITE", "COOKIES.SQLITE", "TORRC", "NOSCRIPT"))
    )

    if any("TOR COMMUNICATION CONFIRMED" in name for name in names):
        total_score += 40

    if any(".ONION" in name for name in names):
        total_score += 40

    if any("PORT 9050" in name or "PORT 9150" in name for name in names):
        total_score += 30

    if any("TOR EXECUTION" in name or "PREFETCH" in name for name in names):
        total_score += 30

    if any("TOR PROCESS" in name or "TOR BROWSER" in name for name in names):
        total_score += 30

    if application_hits >= 2:
        total_score += 30
    elif application_hits == 1:
        total_score += 18

    if any("POSSIBLE TOR TRAFFIC" in name or "TOR-LIKE" in name for name in names):
        total_score += 20

    if any("TOR DATA FLOW" in name for name in names):
        total_score += 25
    elif any("ENCRYPTED DATA FLOW" in name or "ENCRYPTED TRANSPORT" in name for name in names):
        total_score += 15
    elif any("DATA FLOW" in name for name in names):
        total_score += 10

    if any("TOR-LIKE MULTI-NODE TRAFFIC" in name for name in names):
        total_score += 20

    if any("VPN" in name for name in names):
        total_score += 10

    if any("REMOVABLE STORAGE" in name for name in names):
        total_score += 10

    if any("EVENT LOG CLEARED" in name or "EVENT 1102" in name for name in names):
        total_score += 10

    has_execution = any("PREFETCH" in name or "TOR EXECUTION" in name for name in names)
    has_transport = any("DATA FLOW" in name for name in names)
    has_pcap = any("TOR COMMUNICATION CONFIRMED" in name for name in names)

    if has_execution and has_transport:
        total_score += 15

    if has_pcap and has_execution:
        total_score += 15

    if application_hits and has_execution:
        total_score += 10

    active_layers = sum(bool(layer_hits.get(layer)) for layer in layer_hits)
    if active_layers >= 4:
        total_score += 20
    elif active_layers >= 3:
        total_score += 15
    elif active_layers >= 2:
        total_score += 10

    total_score = min(total_score, max_score)

    if total_score >= 85:
        determination = "CONFIRMED: Strong multi-layer forensic evidence proves Tor usage."
    elif total_score >= 65:
        determination = "HIGHLY LIKELY: Multiple strong indicators of Tor activity."
    elif total_score >= 40:
        determination = "PROBABLE: Evidence suggests Tor usage."
    elif total_score >= 20:
        determination = "SUSPICIOUS: Indicators present but not conclusive."
    else:
        determination = "NO EVIDENCE: No significant Tor artifacts detected."

    return total_score, determination

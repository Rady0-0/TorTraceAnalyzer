def _extract_signal_text(detection):
    parts = [
        detection.get("file_name"),
        detection.get("artifact"),
        detection.get("evidence_match"),
        detection.get("message"),
        detection.get("file_path"),
    ]
    return " | ".join(str(part).upper() for part in parts if part)


def calculate_fci(layer_hits, all_detections):
    total_score = 0
    max_score = 100
    signals = [_extract_signal_text(detection) for detection in all_detections]
    application_hits = sum(
        1
        for signal in signals
        if any(
            indicator in signal
            for indicator in ("PLACES.SQLITE", "COOKIES.SQLITE", "TORRC", "NOSCRIPT", "TOR BROWSER SHORTCUT")
        )
    )

    if any("TOR COMMUNICATION CONFIRMED" in signal for signal in signals):
        total_score += 40

    if any(".ONION" in signal for signal in signals):
        total_score += 40

    if any("PORT 9050" in signal or "PORT 9150" in signal for signal in signals):
        total_score += 30

    if any("TOR EXECUTION" in signal or "PREFETCH" in signal for signal in signals):
        total_score += 30

    if any("TOR PROCESS" in signal or "TOR BROWSER" in signal for signal in signals):
        total_score += 30

    if application_hits >= 2:
        total_score += 30
    elif application_hits == 1:
        total_score += 18

    if any("POSSIBLE TOR TRAFFIC" in signal or "TOR-LIKE" in signal for signal in signals):
        total_score += 20

    if any("TOR DATA FLOW" in signal for signal in signals):
        total_score += 25
    elif any("ENCRYPTED DATA FLOW" in signal or "ENCRYPTED TRANSPORT" in signal for signal in signals):
        total_score += 15
    elif any("DATA FLOW" in signal for signal in signals):
        total_score += 10

    if any("TOR-LIKE MULTI-NODE TRAFFIC" in signal for signal in signals):
        total_score += 20

    if any("VPN" in signal for signal in signals):
        total_score += 10

    if any("EVENT LOG CLEARED" in signal or "EVENT 1102" in signal for signal in signals):
        total_score += 10

    has_execution = any("PREFETCH" in signal or "TOR EXECUTION" in signal for signal in signals)
    has_transport = any("DATA FLOW" in signal for signal in signals)
    has_pcap = any("TOR COMMUNICATION CONFIRMED" in signal for signal in signals)

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

def _extract_signal_text(detection):
    parts = [
        detection.get("file_name"),
        detection.get("artifact"),
        detection.get("evidence_match"),
        detection.get("message"),
        detection.get("file_path"),
    ]
    return " | ".join(str(part).upper() for part in parts if part)


def _item(severity, title, explanation):
    return f"{severity} | {title} | {explanation}"


def correlate_artifacts(layer_hits, all_detections):
    correlations = []
    signals = [_extract_signal_text(detection) for detection in all_detections]

    has_execution = any(
        "PREFETCH" in signal or "TOR PROCESS" in signal or "TOR EXECUTION" in signal
        for signal in signals
    )
    has_direct_tor = any(
        any(port in signal for port in ("PORT 9001", "PORT 9030", "PORT 9050", "PORT 9150"))
        or ".ONION" in signal
        or "TOR COMMUNICATION CONFIRMED" in signal
        for signal in signals
    )
    has_behavioral = any(
        "POSSIBLE TOR" in signal or "TOR-LIKE" in signal
        for signal in signals
    )
    has_application = any(
        indicator in signal
        for signal in signals
        for indicator in ("PLACES.SQLITE", "COOKIES.SQLITE", "TORRC", "NOSCRIPT", "TOR BROWSER SHORTCUT")
    )
    has_vpn = any("VPN" in signal for signal in signals)
    has_transport = any(
        "DATA FLOW" in signal or "ENCRYPTED TRANSPORT" in signal or "TCP DATA FLOW" in signal
        for signal in signals
    )
    has_pcap_tor = any("TOR COMMUNICATION CONFIRMED" in signal for signal in signals)
    has_pcap_behavior = any("TOR-LIKE MULTI-NODE TRAFFIC" in signal for signal in signals)
    has_exfiltration = any("EXFILTRATION" in signal for signal in signals)

    if has_execution:
        correlations.append(
            _item(
                "HIGH",
                "Tor execution evidence",
                "System or memory artifacts suggest Tor was executed on the device.",
            )
        )

    if has_application:
        correlations.append(
            _item(
                "HIGH",
                "Tor application artifacts",
                "Tor Browser or Tor configuration artifacts were identified in disk-style evidence.",
            )
        )

    if has_direct_tor:
        correlations.append(
            _item(
                "CRITICAL",
                "Direct Tor indicators",
                "Known Tor ports or onion-service references were detected in the evidence.",
            )
        )

    if has_pcap_tor:
        correlations.append(
            _item(
                "CRITICAL",
                "Packet-level Tor confirmation",
                "PCAP analysis showed traffic using Tor-related network behavior or ports.",
            )
        )

    if has_behavioral and not has_direct_tor:
        correlations.append(
            _item(
                "HIGH",
                "Tor-like network behavior",
                "The network pattern looks consistent with Tor-style routing, even without a direct Tor port hit.",
            )
        )

    if has_pcap_behavior:
        correlations.append(
            _item(
                "HIGH",
                "Multi-node encrypted pattern",
                "Encrypted traffic was spread across many nodes, which is consistent with anonymized routing.",
            )
        )

    if has_vpn and (has_execution or has_behavioral or has_pcap_tor):
        correlations.append(
            _item(
                "HIGH",
                "Layered anonymization",
                "VPN evidence appeared together with Tor-related activity, suggesting stacked privacy tooling.",
            )
        )
    elif has_vpn:
        correlations.append(
            _item(
                "MEDIUM",
                "VPN activity",
                "VPN-related evidence was found, which may hide or redirect traffic.",
            )
        )

    if has_transport:
        correlations.append(
            _item(
                "MEDIUM",
                "Transport activity",
                "The transport layer showed active data movement or encrypted transfer.",
            )
        )

    if has_execution and (has_transport or has_pcap_tor):
        correlations.append(
            _item(
                "CRITICAL",
                "Execution plus transfer evidence",
                "Tor execution evidence appeared together with transport or packet-transfer evidence in the same case.",
            )
        )
    elif has_application and (has_direct_tor or has_behavioral):
        correlations.append(
            _item(
                "HIGH",
                "Application plus network support",
                "Tor application artifacts are reinforced by separate network-side indicators in the same case.",
            )
        )
    elif has_behavioral and (has_transport or has_pcap_behavior):
        correlations.append(
            _item(
                "HIGH",
                "Network pattern plus transfer evidence",
                "Transport evidence supports the Tor-like routing pattern seen elsewhere in the case.",
            )
        )

    if has_exfiltration:
        correlations.append(
            _item(
                "CRITICAL",
                "Potential exfiltration",
                "The evidence indicates possible outbound data removal or exfiltration behavior.",
            )
        )

    active_layers = sum(bool(layer_hits.get(layer)) for layer in layer_hits)
    if active_layers >= 4:
        correlations.append(
            _item(
                "CRITICAL",
                "Cross-layer support",
                "Detections were found across four or more forensic layers, which strengthens confidence.",
            )
        )
    elif active_layers >= 3:
        correlations.append(
            _item(
                "HIGH",
                "Multi-layer support",
                "Detections were found across three forensic layers, giving stronger support than a single-source hit.",
            )
        )
    elif active_layers == 2:
        correlations.append(
            _item(
                "MEDIUM",
                "Limited cross-layer support",
                "Two forensic layers contributed detections, but the case is not yet broadly corroborated.",
            )
        )

    if not correlations:
        correlations.append(
            _item(
                "LOW",
                "Weak correlation",
                "No strong combination of Tor-related indicators was found across the analyzed evidence.",
            )
        )

    summary_items = []
    for item in correlations:
        parts = [part.strip() for part in item.split("|", 2)]
        if len(parts) == 3:
            summary_items.append(f"{parts[0]} - {parts[1]}")
        else:
            summary_items.append(item)

    return {
        "correlations": correlations,
        "summary": "; ".join(summary_items),
    }

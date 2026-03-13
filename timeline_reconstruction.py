def build_timeline(results):

    timeline = []

    if results["memory"]:
        timeline.append("Tor process execution detected in system memory")

    if results["system"]:
        timeline.append("System execution artifacts created (Prefetch / NTFS traces)")

    if results["network"]:
        timeline.append("Tor network communication established (TLS / SOCKS traffic)")

    if results["application"]:
        timeline.append("Tor browser activity detected (browser artifacts)")

    reconstruction = []

    if results["memory"] and results["system"]:
        reconstruction.append("Tor execution confirmed by memory and system artifacts")

    if results["memory"] and results["network"]:
        reconstruction.append("Tor process likely initiated network relay connection")

    if results["network"] and results["application"]:
        reconstruction.append("Tor browsing activity inferred from network and browser artifacts")

    if len(timeline) >= 3:
        reconstruction.append("Multi-layer forensic evidence indicates Tor-based activity")

    return {
        "timeline": timeline,
        "reconstruction": reconstruction
    }
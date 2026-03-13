def correlate_artifacts(results):

    correlations = []
    confidence_boost = 0

    memory = results.get("memory", False)
    system = results.get("system", False)
    network = results.get("network", False)
    application = results.get("application", False)

    if memory and system:
        correlations.append("Tor execution confirmed by memory and system artifacts")
        confidence_boost += 10

    if memory and network:
        correlations.append("Active Tor connection inferred from memory and network indicators")
        confidence_boost += 10

    if system and application:
        correlations.append("Tor browser usage supported by system and application artifacts")
        confidence_boost += 5

    if network and application:
        correlations.append("Possible Tor browsing activity based on network and application traces")
        confidence_boost += 5

    return {
        "correlations": correlations,
        "confidence_boost": confidence_boost
    }
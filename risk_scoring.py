def calculate_fci(layer_hits, all_detections):
    """
    Forensic Confidence Index (FCI) Calculation.
    
    This module uses a weighted model where the score is determined by the 
    'Probative Value' of each unique artifact found across all layers.
    """
    
    # 1. ARTIFACT CRITICALITY WEIGHTS
    # These must be a 1:1 match with the 'file_name' strings in analysis modules.
    critical_artifacts = {
        ".ONION ADDRESS": 40,      # HIGH: Proves Tor hidden service interaction.
        "USERASSIST (TOR)": 35,    # HIGH: Proves intentional human launch.
        "PORT 9150": 30,           # MED-HIGH: Direct evidence of TBB traffic.
        "PORT 9050": 30,           # MED-HIGH: Direct evidence of Tor SOCKS traffic.
        "TOR PREFETCH": 25,        # MED: Proves the binary was run on Windows.
        "SETTINGS.JSON": 25,       # MED: Proves user-modified security levels.
        "TOR.EXE": 20,             # MED: Direct binary match in memory or disk.
        "EVENT 1102": 20,          # MED: Evidence of 'Log-Wiping' behavior.
        "VPN PREFETCH": 15,        # LOW-MED: Supportive evidence of anonymization software.
        "REMOVABLE STORAGE": 15,   # LOW-MED: Evidence of anti-forensic 'Portable' usage.
        "WIREGUARD": 10,           # LOW: Technical VPN protocol detection.
        "VPN/TUNNEL": 10           # LOW: General VPN installation traces.
    }

    total_score = 0
    max_possible_score = 100 

    # 2. SCORING LOGIC
    # We use a set to prevent duplicate points for the same artifact type.
    detected_names = {d['file_name'].upper() for d in all_detections}
    
    for artifact, weight in critical_artifacts.items():
        if artifact in detected_names:
            total_score += weight

    # Cap the score at 100% for the dashboard representation.
    fci_score = min(total_score, max_possible_score)

    # 3. INVESTIGATIVE DETERMINATIONS
    # Thresholds are mapped to standard investigative certainty levels.
    if fci_score >= 85:
        determination = "CONCLUSIVE: Holistic artifact suite confirms active Tor usage."
    elif fci_score >= 60:
        determination = "PROBABLE: Multiple high-integrity signatures suggest Tor activity."
    elif fci_score >= 35:
        determination = "CAUTIONARY: Isolated traces suggest presence without definitive proof of use."
    else:
        determination = "INCONCLUSIVE: No significant forensic signatures identified."

    return fci_score, determination
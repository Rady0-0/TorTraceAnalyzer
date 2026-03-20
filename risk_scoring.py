def calculate_fci(layer_results):
    """
    Calculates the Forensic Confidence Index (FCI) using weighted evidence layers.
    This replaces basic 'Low/High' labels with a professional scoring system.
    
    layer_results: A dictionary like {"memory": True, "network": False, ...}
    """
    # 1. FORENSIC WEIGHTS (Total = 100)
    # Network and Application are weighted higher because they represent 
    # specific software footprints and active external communication.
    weights = {
        "network": 40,      # Highest weight: Proves active traffic to Tor nodes
        "application": 30,  # High weight: Proves the Tor Browser was configured
        "system": 20,       # Medium weight: Proves OS execution (Prefetch/Registry)
        "memory": 10        # Lower weight: Volatile; confirms a process existed
    }

    earned_points = 0
    total_possible = sum(weights.values())

    # 2. CALCULATION LOGIC
    for layer, weight in weights.items():
        # We check if the layer found any artifacts (True)
        if layer_results.get(layer.lower()):
            earned_points += weight

    # Final Percentage Calculation
    fci_score = (earned_points / total_possible) * 100

    # 3. PROFESSIONAL DETERMINATIONS (Requirement 5)
    # These conclusions are based on standard investigative certainty levels.
    if fci_score >= 90:
        conclusion = "CONCLUSIVE: Definitive evidence of active Tor Browser usage."
    elif fci_score >= 60:
        conclusion = "PROBABLE: Strong technical indicators suggest Tor activity."
    elif fci_score >= 30:
        conclusion = "CAUTIONARY: Isolated traces detected; may indicate presence without recent use."
    else:
        conclusion = "INCONCLUSIVE: No significant forensic signatures identified."

    return fci_score, conclusion
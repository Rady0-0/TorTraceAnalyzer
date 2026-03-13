def calculate_risk(results):

    score = 0

    # Assign weights to each forensic layer
    weights = {
        "memory": 30,
        "system": 25,
        "network": 25,
        "application": 20
    }

    for layer, detected in results.items():
        if detected:
            score += weights[layer]

    # Determine confidence level
    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level
import re

def detect_tor_relay(data):

    # Known Tor relay prefixes (simplified detection)
    tor_ip_patterns = [
        "185.220",
        "51.15",
        "89.234",
        "171.25"
    ]

    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', data)

    detected = set()

    for ip in ips:
        for prefix in tor_ip_patterns:
            if ip.startswith(prefix):
                detected.add(ip)

    return list(detected)
import os
import csv
import json
from tor_relay_detection import detect_tor_relay


def read_file_content(file):

    extension = os.path.splitext(file)[1].lower()

    try:

        if extension in [".txt", ".log"]:
            with open(file, "r", errors="ignore") as f:
                return f.read().lower()

        elif extension == ".csv":
            data = ""
            with open(file, newline='', errors="ignore") as f:
                reader = csv.reader(f)
                for row in reader:
                    data += " ".join(row).lower()
            return data

        elif extension == ".json":
            with open(file, "r", errors="ignore") as f:
                return json.dumps(json.load(f)).lower()

        else:
            return ""

    except:
        return ""


def check_network(file):

    data = read_file_content(file)

    network_indicators = [
        "tor",
        "relay",
        "onion",
        "tls",
        "9050",
        "9001",
        "9030",
        "socks",
        "directory request"
    ]

    detected = []

    for indicator in network_indicators:
        if indicator in data:
            detected.append(indicator)

    # ----- TOR RELAY IP DETECTION -----
    tor_relays = detect_tor_relay(data)

    if tor_relays:
        detected.append("tor relay ip: " + ", ".join(tor_relays))

    if detected:
        return "[Network Layer] Tor network indicators detected: " + ", ".join(detected)

    else:
        return "[Network Layer] No Tor network indicators detected"
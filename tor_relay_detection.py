import re

def load_tor_nodes():

    nodes = set()

    try:
        with open("tor_nodes.txt", "r") as f:
            for line in f:
                nodes.add(line.strip())
    except:
        pass

    return nodes


def detect_tor_relay(data):

    tor_nodes = load_tor_nodes()

    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', data)

    detected = []

    for ip in ips:
        if ip in tor_nodes:
            detected.append(ip)

    return detected
import re


TOR_PORTS = ("9001", "9030", "9050", "9150")
NO_TIMESTAMPS = {"modified": "N/A", "created": "N/A", "accessed": "N/A"}


# Strict public IP validation.
def is_valid_public_ip(ip):
    try:
        parts = list(map(int, ip.split(".")))
        if len(parts) != 4:
            return False
        if parts[0] == 0:
            return False
        if parts[0] == 10:
            return False
        if parts[0] == 127:
            return False
        if parts[0] == 169 and parts[1] == 254:
            return False
        if parts[0] == 192 and parts[1] == 168:
            return False
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return False
        if parts[0] >= 224:
            return False
        return True
    except Exception:
        return False


# Extract valid IPs.
def extract_valid_ips(content):
    raw_ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", content)
    return list({ip for ip in raw_ips if is_valid_public_ip(ip)})


# Forensic report filter.
def is_forensic_report(content):
    report_keywords = [
        "autopsy",
        "artifact",
        "file path",
        "metadata",
        "standard information",
        "attribute id",
        "img_",
        "vol_",
        "partition",
        "analysis report",
    ]
    return any(keyword in content for keyword in report_keywords)


# Representative IP string for detections.
def extract_ip_location(content):
    ips = extract_valid_ips(content)
    return f"Packet Stream [IP: {ips[0]}]" if ips else "Network Stream"


# Main network analysis.
def check_network(file_data):
    content = file_data.get("content", "").lower()
    results = []

    if is_forensic_report(content):
        return results

    valid_ips = extract_valid_ips(content)
    filtered_ips = [ip for ip in valid_ips if not ip.endswith(".0") and not ip.endswith(".1")]
    tcp_connections = len(re.findall(r"\btcp\b", content))
    tls_connections = len(re.findall(r"\btls\b", content)) + len(re.findall(r":443", content))

    for port in TOR_PORTS:
        if re.search(rf"(?::|\s){port}(?!\d)", content):
            results.append(
                {
                    "layer": "Network",
                    "status": "Detected",
                    "file_name": f"PORT {port}",
                    "file_path": extract_ip_location(content),
                    "message": f"Direct Tor communication via port {port}.",
                    "evidence_match": f"Port {port}",
                    "disk_timestamps": dict(NO_TIMESTAMPS),
                }
            )

    vpn_keywords = ["wireguard", "openvpn"]
    if any(vpn in content for vpn in vpn_keywords) and len(filtered_ips) > 5:
        results.append(
            {
                "layer": "Network",
                "status": "Detected",
                "file_name": "VPN/TUNNEL",
                "file_path": f"Network Context [{len(filtered_ips)} IPs]",
                "message": "VPN-related network activity detected.",
                "evidence_match": ", ".join(vpn_keywords),
                "disk_timestamps": dict(NO_TIMESTAMPS),
            }
        )

    if len(filtered_ips) > 15 and (tcp_connections > 50 or tls_connections > 50):
        results.append(
            {
                "layer": "Network",
                "status": "Suspicious",
                "file_name": "POSSIBLE TOR TRAFFIC",
                "file_path": f"Multiple Nodes [{len(filtered_ips)} public IPs]",
                "message": "High-volume encrypted connections to diverse nodes.",
                "evidence_match": f"IPs: {filtered_ips[:5]}",
                "disk_timestamps": dict(NO_TIMESTAMPS),
            }
        )

    if ".onion" in content:
        results.append(
            {
                "layer": "Network",
                "status": "Detected",
                "file_name": ".ONION DOMAIN",
                "file_path": "Application/Network Logs",
                "message": "Tor hidden service communication detected.",
                "evidence_match": ".onion",
                "disk_timestamps": dict(NO_TIMESTAMPS),
            }
        )

    return results

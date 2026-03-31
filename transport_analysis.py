import re


TOR_PORTS = ("9001", "9030", "9050", "9150")
NO_TIMESTAMPS = {"modified": "N/A", "created": "N/A", "accessed": "N/A"}


# Valid public IP filter.
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
    valid_ips = []
    for ip in raw_ips:
        if is_valid_public_ip(ip):
            valid_ips.append(ip)
    return list(set(valid_ips))


def extract_tor_ports(content):
    found_ports = []
    for port in TOR_PORTS:
        if re.search(rf"(?::|\s){port}(?!\d)", content):
            found_ports.append(port)
    return found_ports


# Detect if content is a forensic report rather than transport evidence.
def is_forensic_report(content):
    report_keywords = [
        "autopsy",
        "report",
        "artifact",
        "file path",
        "standard information",
        "attribute",
        "img_",
        "vol_",
        "partition",
        "metadata",
    ]
    return any(keyword in content for keyword in report_keywords)


# Main transport analysis.
def analyze_transport(file_data):
    content = file_data.get("content", "").lower()
    results = []

    if is_forensic_report(content):
        return results

    valid_ips = extract_valid_ips(content)
    detected_ports = extract_tor_ports(content)
    tcp_count = len(re.findall(r"\btcp\b", content))
    tls_count = len(re.findall(r"\btls\b", content)) + len(re.findall(r":443", content))
    tor_port_summary = ", ".join(detected_ports) if detected_ports else "None detected"

    if len(valid_ips) < 5:
        return results

    if tcp_count > 50:
        message = "High-volume TCP connections indicate real data transmission."
        evidence = f"TCP count: {tcp_count}"
        path = f"Transport Layer [{len(valid_ips)} IPs]"
        if detected_ports:
            message += f" Tor-related ports observed: {tor_port_summary}."
            evidence += f" | Tor ports: {tor_port_summary}"
            path += f" [Tor ports: {tor_port_summary}]"
        results.append(
            {
                "layer": "Transport",
                "status": "Detected",
                "file_name": "TCP DATA FLOW",
                "file_path": path,
                "message": message,
                "evidence_match": evidence,
                "disk_timestamps": dict(NO_TIMESTAMPS),
            }
        )

    if tls_count > 30:
        message = "Sustained encrypted transport detected."
        evidence = f"TLS count: {tls_count}"
        path = "TLS/HTTPS Channel"
        if detected_ports:
            message += f" Tor-related ports observed: {tor_port_summary}."
            evidence += f" | Tor ports: {tor_port_summary}"
            path += f" [Tor ports: {tor_port_summary}]"
        results.append(
            {
                "layer": "Transport",
                "status": "Detected",
                "file_name": "ENCRYPTED TRANSPORT",
                "file_path": path,
                "message": message,
                "evidence_match": evidence,
                "disk_timestamps": dict(NO_TIMESTAMPS),
            }
        )

    for port in detected_ports:
        results.append(
            {
                "layer": "Transport",
                "status": "Detected",
                "file_name": f"PORT {port}",
                "file_path": "Tor Transport Channel",
                "message": f"Tor communication via port {port}.",
                "evidence_match": f"Port {port}",
                "disk_timestamps": dict(NO_TIMESTAMPS),
            }
        )

    if len(valid_ips) > 10 and (tcp_count > 50 or tls_count > 30):
        message = "Pattern suggests actual data movement across the network."
        evidence = f"IPs: {valid_ips[:5]}"
        path = f"Multiple External Nodes [{len(valid_ips)} IPs]"
        if detected_ports:
            message += f" Tor-related ports observed: {tor_port_summary}."
            evidence += f" | Tor ports: {tor_port_summary}"
            path += f" [Tor ports: {tor_port_summary}]"
        results.append(
            {
                "layer": "Transport",
                "status": "Suspicious",
                "file_name": "POSSIBLE DATA TRANSPORT",
                "file_path": path,
                "message": message,
                "evidence_match": evidence,
                "disk_timestamps": dict(NO_TIMESTAMPS),
            }
        )

    return results

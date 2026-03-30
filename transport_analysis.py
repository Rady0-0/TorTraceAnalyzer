import re


# ============================================
# 1. VALID PUBLIC IP FILTER
# ============================================
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

    except:
        return False


# ============================================
# 2. EXTRACT VALID IPS
# ============================================
def extract_valid_ips(content):
    raw_ips = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', content)

    valid_ips = []
    for ip in raw_ips:
        if is_valid_public_ip(ip):
            valid_ips.append(ip)

    return list(set(valid_ips))


# ============================================
# 🔥 3. DETECT IF CONTENT IS JUST REPORT TEXT
# ============================================
def is_forensic_report(content):
    report_keywords = [
        "autopsy", "report", "artifact", "file path",
        "standard information", "attribute", "img_",
        "vol_", "partition", "metadata"
    ]

    return any(k in content for k in report_keywords)


# ============================================
# 4. MAIN TRANSPORT ANALYSIS (FIXED)
# ============================================
def analyze_transport(file_data):
    content = file_data.get("content", "").lower()
    ts_metadata = file_data.get("timestamps", {})

    results = []

    # 🔥 BLOCK FALSE POSITIVES (CRITICAL FIX)
    if is_forensic_report(content):
        return results  # DO NOT ANALYZE REPORT TEXT

    valid_ips = extract_valid_ips(content)

    tcp_count = len(re.findall(r'\btcp\b', content))
    tls_count = len(re.findall(r'\btls\b', content)) + len(re.findall(r':443', content))

    # ============================================
    # 🔥 STRICT CONDITIONS (ALL MUST PASS)
    # ============================================
    if len(valid_ips) < 5:
        return results  # Not real network behavior

    # ============================================
    # 1. TCP DATA FLOW
    # ============================================
    if tcp_count > 50:
        results.append({
            "layer": "Transport",
            "status": "Detected",
            "file_name": "TCP DATA FLOW",
            "file_path": f"Transport Layer [{len(valid_ips)} IPs]",
            "message": "High-volume TCP connections indicate real data transmission.",
            "evidence_match": f"TCP count: {tcp_count}",
            "disk_timestamps": ts_metadata
        })

    # ============================================
    # 2. ENCRYPTED TRANSPORT
    # ============================================
    if tls_count > 30:
        results.append({
            "layer": "Transport",
            "status": "Detected",
            "file_name": "ENCRYPTED TRANSPORT",
            "file_path": "TLS/HTTPS Channel",
            "message": "Sustained encrypted transport detected.",
            "evidence_match": f"TLS count: {tls_count}",
            "disk_timestamps": ts_metadata
        })

    # ============================================
    # 3. TOR TRANSPORT CHANNEL
    # ============================================
    tor_ports = ["9001", "9030", "9050", "9150"]

    for port in tor_ports:
        if re.search(rf"(?::|\s){port}(?!\d)", content):
            results.append({
                "layer": "Transport",
                "status": "Detected",
                "file_name": f"PORT {port}",
                "file_path": "Tor Transport Channel",
                "message": f"Tor communication via port {port}.",
                "evidence_match": f"Port {port}",
                "disk_timestamps": ts_metadata
            })

    # ============================================
    # 4. DATA TRANSPORT (REALISTIC)
    # ============================================
    if len(valid_ips) > 10 and (tcp_count > 50 or tls_count > 30):
        results.append({
            "layer": "Transport",
            "status": "Suspicious",
            "file_name": "POSSIBLE DATA TRANSPORT",
            "file_path": f"Multiple External Nodes [{len(valid_ips)} IPs]",
            "message": "Pattern suggests actual data movement across network.",
            "evidence_match": f"IPs: {valid_ips[:5]}",
            "disk_timestamps": ts_metadata
        })

    return results
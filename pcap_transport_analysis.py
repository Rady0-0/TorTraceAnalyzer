import os
import tempfile
from ipaddress import ip_address


TOR_PORTS = {9001, 9030, 9050, 9150}


def is_private_ip(ip):
    try:
        address = ip_address(ip)
    except ValueError:
        return True

    return address.is_private or address.is_loopback or address.is_link_local or address.is_multicast


def _file_timestamps(file_path):
    try:
        stats = os.stat(file_path)
    except OSError:
        return {"modified": "N/A", "created": "N/A", "accessed": "N/A"}

    return {
        "modified": _format_ts(stats.st_mtime),
        "created": _format_ts(stats.st_ctime),
        "accessed": _format_ts(stats.st_atime),
    }


def _format_ts(raw_ts):
    from datetime import datetime

    return datetime.fromtimestamp(raw_ts).strftime("%Y-%m-%d %H:%M:%S")


def _detection(file_name, message, evidence_match, file_path, timestamps, status="Detected"):
    return {
        "layer": "Transport",
        "status": status,
        "file_name": file_name,
        "file_path": file_path,
        "message": message,
        "evidence_match": evidence_match,
        "disk_timestamps": timestamps,
    }


def analyze_pcap_transport(file_path):
    cache_root = os.path.join(tempfile.gettempdir(), "TorTraceAnalyzer", "scapy-cache")
    os.makedirs(cache_root, exist_ok=True)
    os.environ.setdefault("XDG_CACHE_HOME", cache_root)

    try:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.utils import PcapNgReader, PcapReader
    except Exception as exc:
        raise RuntimeError("PCAP analysis requires a working Scapy installation.") from exc

    timestamps = _file_timestamps(file_path)
    results = []
    connections = {}
    total_packets = 0
    total_bytes = 0
    tor_flows = 0
    encrypted_flows = 0
    public_connections = set()

    reader_class = PcapNgReader if file_path.lower().endswith(".pcapng") else PcapReader
    reader = reader_class(file_path)
    try:
        for packet in reader:
            if IP not in packet:
                continue

            src = packet[IP].src
            dst = packet[IP].dst
            size = len(packet)
            sport = None
            dport = None
            protocol = "UNKNOWN"

            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                protocol = "TCP"
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                protocol = "UDP"

            key = (src, dst, sport, dport, protocol)
            connections.setdefault(key, {"packets": 0, "bytes": 0})
            connections[key]["packets"] += 1
            connections[key]["bytes"] += size

            total_packets += 1
            total_bytes += size
    finally:
        reader.close()

    for (src, dst, sport, dport, protocol), data in connections.items():
        outbound = is_private_ip(src) and not is_private_ip(dst)
        inbound = not is_private_ip(src) and is_private_ip(dst)
        direction = "Outbound" if outbound else "Inbound" if inbound else "Internal"

        if not is_private_ip(dst):
            public_connections.add(dst)

        is_tor = dport in TOR_PORTS or sport in TOR_PORTS
        is_encrypted = dport == 443 or sport == 443

        if is_tor:
            tor_flows += 1
        if is_encrypted:
            encrypted_flows += 1

        if data["packets"] > 20 or data["bytes"] > 50000 or is_tor:
            file_name = "DATA FLOW"
            if is_tor:
                file_name = "TOR DATA FLOW"
            elif is_encrypted:
                file_name = "ENCRYPTED DATA FLOW"

            flow_path = f"{src}:{sport} -> {dst}:{dport}"
            results.append(
                _detection(
                    file_name=file_name,
                    message=f"{direction} {protocol} traffic ({data['packets']} packets)",
                    evidence_match=f"Bytes: {data['bytes']}",
                    file_path=flow_path,
                    timestamps=timestamps,
                )
            )

    if tor_flows > 0:
        results.append(
            _detection(
                file_name="TOR COMMUNICATION CONFIRMED",
                message="Direct Tor ports observed in packet capture.",
                evidence_match=f"Tor flows: {tor_flows}",
                file_path=os.path.basename(file_path),
                timestamps=timestamps,
            )
        )

    if len(public_connections) > 20 and encrypted_flows > 10:
        results.append(
            _detection(
                file_name="TOR-LIKE MULTI-NODE TRAFFIC",
                message="High-volume encrypted connections to many public nodes.",
                evidence_match=f"Encrypted flows: {encrypted_flows}",
                file_path=f"{len(public_connections)} external nodes",
                timestamps=timestamps,
                status="Suspicious",
            )
        )

    results.append(
        _detection(
            file_name="PCAP SUMMARY",
            message=f"Total packets: {total_packets}",
            evidence_match=f"Total bytes: {total_bytes}",
            file_path=os.path.basename(file_path),
            timestamps=timestamps,
        )
    )

    return results

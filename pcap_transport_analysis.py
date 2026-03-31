import os
import tempfile
from ipaddress import ip_address


TOR_PORTS = {9001, 9030, 9050, 9150}
NO_TIMESTAMPS = {"modified": "N/A", "created": "N/A", "accessed": "N/A"}


class PcapAnalysisError(RuntimeError):
    pass


# Network helpers.
def is_private_ip(ip):
    try:
        address = ip_address(ip)
    except ValueError:
        return True
    return address.is_private or address.is_loopback or address.is_link_local or address.is_multicast


# Shared detection builder.
def _detection(layer, file_name, message, evidence_match, file_path, status="Detected"):
    return {
        "layer": layer,
        "status": status,
        "file_name": file_name,
        "file_path": file_path,
        "message": message,
        "evidence_match": evidence_match,
        "disk_timestamps": dict(NO_TIMESTAMPS),
    }


# Shared Scapy reader.
def _load_scapy_readers():
    cache_root = os.path.join(tempfile.gettempdir(), "TorTraceAnalyzer", "scapy-cache")
    os.makedirs(cache_root, exist_ok=True)
    os.environ.setdefault("XDG_CACHE_HOME", cache_root)

    try:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.utils import PcapNgReader, PcapReader
    except Exception as exc:
        raise PcapAnalysisError("PCAP analysis requires a working Scapy installation.") from exc

    return IP, TCP, UDP, PcapNgReader, PcapReader


def _tor_ports_for_flow(sport, dport):
    return [port for port in (sport, dport) if port in TOR_PORTS]


# Parse a PCAP or PCAPNG once and reuse the flow summary for both layers.
def _read_pcap_summary(file_path):
    IP, TCP, UDP, PcapNgReader, PcapReader = _load_scapy_readers()
    reader_class = PcapNgReader if file_path.lower().endswith(".pcapng") else PcapReader

    summary = {
        "connections": {},
        "total_packets": 0,
        "total_bytes": 0,
        "public_nodes": set(),
        "direct_tor_ports": {},
        "encrypted_flow_keys": set(),
        "tor_flow_keys": set(),
    }

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

            flow_key = (src, dst, sport, dport, protocol)
            flow = summary["connections"].setdefault(flow_key, {"packets": 0, "bytes": 0})
            flow["packets"] += 1
            flow["bytes"] += size

            summary["total_packets"] += 1
            summary["total_bytes"] += size

            for endpoint in (src, dst):
                if not is_private_ip(endpoint):
                    summary["public_nodes"].add(endpoint)

            tor_ports = _tor_ports_for_flow(sport, dport)
            if tor_ports:
                summary["tor_flow_keys"].add(flow_key)
                for tor_port in tor_ports:
                    summary["direct_tor_ports"].setdefault(tor_port, {"flows": 0, "nodes": set()})
                    if not is_private_ip(src):
                        summary["direct_tor_ports"][tor_port]["nodes"].add(src)
                    if not is_private_ip(dst):
                        summary["direct_tor_ports"][tor_port]["nodes"].add(dst)

            if sport == 443 or dport == 443:
                summary["encrypted_flow_keys"].add(flow_key)
    finally:
        reader.close()

    summary["tor_flows"] = len(summary["tor_flow_keys"])
    summary["encrypted_flows"] = len(summary["encrypted_flow_keys"])
    for tor_port, port_info in summary["direct_tor_ports"].items():
        port_info["flows"] = len(
            {
                flow_key
                for flow_key in summary["tor_flow_keys"]
                if tor_port in _tor_ports_for_flow(flow_key[2], flow_key[3])
            }
        )

    return summary


# Build network-layer detections from packet captures.
def _build_network_results(file_path, summary):
    results = []
    direct_tor_ports = summary["direct_tor_ports"]
    public_node_count = len(summary["public_nodes"])

    for tor_port in sorted(direct_tor_ports):
        port_info = direct_tor_ports[tor_port]
        node_count = len(port_info["nodes"])
        results.append(
            _detection(
                layer="Network",
                file_name=f"PORT {tor_port}",
                message=f"Packet capture shows direct communication through Tor-related port {tor_port}.",
                evidence_match=f"Flows: {port_info['flows']} | Public nodes: {node_count}",
                file_path=f"{os.path.basename(file_path)} [Tor port {tor_port}]",
            )
        )

    if public_node_count >= 10 and summary["encrypted_flows"] >= 5:
        results.append(
            _detection(
                layer="Network",
                file_name="POSSIBLE TOR TRAFFIC",
                message="Traffic pattern shows many public nodes with sustained encrypted flows.",
                evidence_match=f"Public nodes: {public_node_count} | Encrypted flows: {summary['encrypted_flows']}",
                file_path=os.path.basename(file_path),
                status="Suspicious",
            )
        )

    return results


# Build transport-layer detections from packet captures.
def _build_transport_results(file_path, summary):
    results = []

    for (src, dst, sport, dport, protocol), flow_data in summary["connections"].items():
        tor_ports = _tor_ports_for_flow(sport, dport)
        if not tor_ports:
            continue

        outbound = is_private_ip(src) and not is_private_ip(dst)
        inbound = not is_private_ip(src) and is_private_ip(dst)
        direction = "Outbound" if outbound else "Inbound" if inbound else "Internal"
        tor_port_summary = ", ".join(str(port) for port in sorted(set(tor_ports)))

        results.append(
            _detection(
                layer="Transport",
                file_name="TOR DATA FLOW",
                message=(
                    f"{direction} {protocol} traffic ({flow_data['packets']} packets) "
                    f"through Tor-related port(s): {tor_port_summary}."
                ),
                evidence_match=f"Tor ports: {tor_port_summary} | Bytes: {flow_data['bytes']}",
                file_path=f"{src} -> {dst} [Tor ports: {tor_port_summary}]",
            )
        )

    if summary["tor_flows"] > 0:
        results.append(
            _detection(
                layer="Transport",
                file_name="TOR COMMUNICATION CONFIRMED",
                message="Direct Tor ports were observed in packet transport flows.",
                evidence_match=(
                    f"Tor flows: {summary['tor_flows']} | Known Tor ports: 9001, 9030, 9050, 9150"
                ),
                file_path=os.path.basename(file_path),
            )
        )

    if len(summary["public_nodes"]) >= 20 and summary["encrypted_flows"] >= 10:
        results.append(
            _detection(
                layer="Transport",
                file_name="TOR-LIKE MULTI-NODE TRAFFIC",
                message="High-volume encrypted transport reached many public nodes.",
                evidence_match=f"Public nodes: {len(summary['public_nodes'])} | Encrypted flows: {summary['encrypted_flows']}",
                file_path=os.path.basename(file_path),
                status="Suspicious",
            )
        )

    return results


# Analyze both network and transport layers from the same PCAP parse.
def analyze_pcap_layers(file_path):
    summary = _read_pcap_summary(file_path)
    return _build_network_results(file_path, summary), _build_transport_results(file_path, summary)


# Backward-compatible transport-only entry point.
def analyze_pcap_transport(file_path):
    _network_results, transport_results = analyze_pcap_layers(file_path)
    return transport_results


# Explicit network-layer entry point for PCAPs.
def analyze_pcap_network(file_path):
    network_results, _transport_results = analyze_pcap_layers(file_path)
    return network_results

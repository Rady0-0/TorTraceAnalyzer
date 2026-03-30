import json
import os
from datetime import datetime

from application_analysis import check_application
from artifact_correlation import correlate_artifacts
from file_parser import parse_forensic_file
from memory_analysis import check_memory
from network_analysis import check_network
from report_generator import generate_report
from risk_scoring import calculate_fci
from system_analysis import check_system
from timeline_reconstruction import build_timeline
from transport_analysis import analyze_transport


ACTIVE_LAYERS = ("memory", "system", "network", "application", "transport")


def _empty_result():
    return {
        "evidence_files": [],
        "layer_results": {layer: [] for layer in ACTIVE_LAYERS},
        "layer_hits": {layer: False for layer in ACTIVE_LAYERS},
        "all_detections": [],
        "correlation": {"correlations": [], "summary": ""},
        "fci_score": 0,
        "determination": "NO EVIDENCE: No significant Tor artifacts detected.",
        "timeline": {"events": [], "summary": "0 timeline events reconstructed (MACB format)."},
        "report_path": "",
    }


def _emit(event_callback, event_type, **payload):
    if event_callback:
        event_callback({"type": event_type, **payload})


def _emit_console_header():
    print("=" * 70)
    print("TOR TRACE ANALYZER - MULTI-LAYER FORENSIC SUITE".center(70))
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".center(70))
    print("=" * 70)


def _status(event_callback, message, level="info"):
    _emit(event_callback, "status", message=message, level=level)
    if event_callback is None:
        print(message)


def _progress(event_callback, value, message=None):
    clamped = max(0, min(100, int(value)))
    _emit(event_callback, "progress", value=clamped, message=message or f"{clamped}%")
    if event_callback is None:
        print(f">>> PROGRESS:{clamped}")


def _normalize_timestamps(timestamps):
    safe = timestamps if isinstance(timestamps, dict) else {}
    return {
        "modified": safe.get("modified", "N/A"),
        "created": safe.get("created", "N/A"),
        "accessed": safe.get("accessed", "N/A"),
    }


def normalize_detection(detection, fallback_layer):
    if not isinstance(detection, dict):
        detection = {}

    file_name = detection.get("file_name") or detection.get("artifact") or "UNKNOWN"
    layer_name = detection.get("layer") or fallback_layer

    normalized = {
        "layer": str(layer_name),
        "status": detection.get("status", "Detected"),
        "file_name": str(file_name),
        "file_path": detection.get("file_path", "N/A"),
        "message": detection.get("message", ""),
        "evidence_match": detection.get("evidence_match", ""),
        "disk_timestamps": _normalize_timestamps(detection.get("disk_timestamps")),
    }
    return normalized


def _positive_results(results, fallback_layer):
    normalized_results = []
    for result in results or []:
        normalized = normalize_detection(result, fallback_layer)
        if normalized.get("status") in {"Detected", "Suspicious"}:
            normalized_results.append(normalized)
    return normalized_results


def _collect_evidence_files(inputs):
    evidence_files = []
    for path in inputs:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for filename in files:
                    evidence_files.append(os.path.join(root, filename))
        elif os.path.isfile(path):
            evidence_files.append(path)
    return evidence_files


def _deduplicate_detections(detections):
    seen = set()
    unique = []

    for detection in detections:
        timestamps = detection.get("disk_timestamps", {})
        key = (
            detection.get("layer"),
            detection.get("file_name"),
            detection.get("file_path"),
            detection.get("message"),
            detection.get("evidence_match"),
            timestamps.get("modified"),
            timestamps.get("created"),
            timestamps.get("accessed"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(detection)

    return unique


def _format_detection(detection):
    timestamps = detection.get("disk_timestamps", {})
    return (
        f"STATUS   : {detection.get('status')}\n"
        f"ARTIFACT : {detection.get('file_name')}\n"
        f"PATH     : {detection.get('file_path')}\n"
        f"EVIDENCE : {detection.get('evidence_match')}\n"
        f"MODIFIED : {timestamps.get('modified')}\n"
        f"CREATED  : {timestamps.get('created')}\n"
        f"ACCESSED : {timestamps.get('accessed')}\n"
        f"NOTE     : {detection.get('message')}\n"
        "------------------------------\n"
    )


def _print_console_result(result):
    _emit_console_header()

    for layer, detections in result["layer_results"].items():
        if not detections:
            continue
        print(f"\n[{layer.upper()}]\n")
        for detection in detections:
            print(_format_detection(detection))

    print("\n[FORENSIC CORRELATION SUMMARY]\n")
    print(result["correlation"]["summary"])
    print(f"\nFCI SCORE: {result['fci_score']}%")
    print(f"DETERMINATION: {result['determination']}")

    print("\n[TIMELINE]\n")
    for event in result["timeline"].get("events", []):
        print(
            f"{event.get('time', 'N/A')} | "
            f"{event.get('layer', 'N/A')} | "
            f"{event.get('artifact', 'UNKNOWN')} | "
            f"{event.get('type', '')}"
        )

    if result["report_path"]:
        print(f"\nReport Generated: {result['report_path']}")
    print("INVESTIGATION COMPLETE")


def run_analysis(inputs, event_callback=None):
    result = _empty_result()

    if not inputs:
        _status(event_callback, "[!] ERROR: No forensic sources selected.", level="error")
        return result

    evidence_files = _collect_evidence_files(inputs)
    result["evidence_files"] = evidence_files

    if not evidence_files:
        _status(event_callback, "[!] ERROR: No readable forensic files found.", level="error")
        return result

    _status(
        event_callback,
        f"Processing {len(evidence_files)} evidence file(s) across the forensic pipeline.",
        level="info",
    )
    _progress(event_callback, 5, "Collecting evidence...")

    all_detections = []

    for index, file_path in enumerate(evidence_files, start=1):
        basename = os.path.basename(file_path)
        _status(event_callback, f"Analyzing {basename}", level="info")

        try:
            extension = os.path.splitext(file_path)[1].lower()

            if extension in {".pcap", ".pcapng"}:
                from pcap_transport_analysis import analyze_pcap_transport

                transport_results = _positive_results(
                    analyze_pcap_transport(file_path),
                    "Transport",
                )
                if transport_results:
                    result["layer_results"]["transport"].extend(transport_results)
                    result["layer_hits"]["transport"] = True
                    all_detections.extend(transport_results)
            else:
                parsed = parse_forensic_file(file_path)
                evidence_type = parsed.get("evidence_type", "DISK")

                if evidence_type == "MEMORY":
                    active_checks = [
                        ("memory", check_memory, "Memory"),
                        ("network", check_network, "Network"),
                        ("transport", analyze_transport, "Transport"),
                    ]
                elif evidence_type == "NETWORK":
                    active_checks = [
                        ("network", check_network, "Network"),
                        ("transport", analyze_transport, "Transport"),
                    ]
                else:
                    active_checks = [
                        ("system", check_system, "System"),
                        ("application", check_application, "Application"),
                    ]

                for layer_key, func, fallback_layer in active_checks:
                    normalized_results = _positive_results(func(parsed), fallback_layer)
                    if not normalized_results:
                        continue
                    result["layer_results"][layer_key].extend(normalized_results)
                    result["layer_hits"][layer_key] = True
                    all_detections.extend(normalized_results)
        except Exception as exc:
            _status(
                event_callback,
                f"[!] Error processing {basename}: {exc}",
                level="error",
            )

        progress_value = 5 + int((index / len(evidence_files)) * 65)
        _progress(event_callback, progress_value, f"Processed {index}/{len(evidence_files)} file(s)")

    all_detections = _deduplicate_detections(all_detections)
    result["all_detections"] = all_detections

    _progress(event_callback, 75, "Building correlations...")
    correlation = correlate_artifacts(result["layer_hits"], all_detections)
    result["correlation"] = correlation

    _progress(event_callback, 85, "Calculating FCI...")
    fci_score, determination = calculate_fci(result["layer_hits"], all_detections)
    result["fci_score"] = fci_score
    result["determination"] = determination

    _progress(event_callback, 92, "Reconstructing timeline...")
    timeline = build_timeline(all_detections)
    result["timeline"] = timeline

    _progress(event_callback, 97, "Generating report...")
    try:
        report_path = generate_report(
            all_detections,
            fci_score,
            determination,
            correlation.get("summary", ""),
            timeline,
        )
        result["report_path"] = report_path
    except Exception as exc:
        _status(event_callback, f"[!] Report generation failed: {exc}", level="error")

    _progress(event_callback, 100, "Analysis complete")
    _status(event_callback, "Analysis complete.", level="info")

    if event_callback is None:
        _print_console_result(result)

    return result

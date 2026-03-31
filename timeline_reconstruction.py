from datetime import datetime


def safe_parse(timestamp):
    if not timestamp or timestamp == "N/A":
        return None

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(timestamp, fmt)
        except ValueError:
            continue
    return None


TIMELINE_LAYERS = {"System", "Application"}
GENERIC_PATH_PREFIXES = (
    "memory ",
    "network ",
    "packet stream",
    "transport layer",
    "tls/https channel",
    "tor transport channel",
    "multiple external nodes",
)


def _timeline_relevant_detection(detection):
    layer = str(detection.get("layer", "")).title()
    if layer not in TIMELINE_LAYERS:
        return False

    file_path = str(detection.get("file_path", "")).strip().lower()
    if not file_path:
        return False

    if file_path.startswith(GENERIC_PATH_PREFIXES):
        return False

    return True


def build_timeline(all_detections):
    events = []
    seen = set()

    for detection in all_detections:
        if not _timeline_relevant_detection(detection):
            continue

        timestamps = detection.get("disk_timestamps", {})
        layer = detection.get("layer", "UNKNOWN")
        artifact = detection.get("file_name") or detection.get("artifact") or "UNKNOWN"
        modified_value = timestamps.get("modified")
        if not safe_parse(modified_value):
            continue

        event_key = (modified_value, "MODIFIED", layer, artifact)
        if event_key in seen:
            continue
        seen.add(event_key)
        events.append(
            {
                "time": modified_value,
                "type": "MODIFIED",
                "layer": layer,
                "artifact": artifact,
            }
        )

    events = [event for event in events if safe_parse(event.get("time"))]
    events.sort(key=lambda event: (safe_parse(event["time"]), event["layer"], event["artifact"], event["type"]))

    return {
        "events": events,
        "summary": (
            f"{len(events)} timeline events reconstructed from system/application artifact timestamps. "
            "Network and transport detections are excluded to avoid misleading file-upload times."
        ),
    }

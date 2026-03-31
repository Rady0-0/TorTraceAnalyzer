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
    type_counts = {}

    for detection in all_detections:
        if not _timeline_relevant_detection(detection):
            continue

        timestamps = detection.get("disk_timestamps", {})
        layer = detection.get("layer", "UNKNOWN")
        artifact = detection.get("file_name") or detection.get("artifact") or "UNKNOWN"

        for field_name, event_type in (
            ("modified", "MODIFIED"),
            ("created", "CREATED"),
            ("accessed", "ACCESSED"),
        ):
            timestamp_value = timestamps.get(field_name)
            if not safe_parse(timestamp_value):
                continue

            event_key = (timestamp_value, event_type, layer, artifact)
            if event_key in seen:
                continue

            seen.add(event_key)
            type_counts[event_type] = type_counts.get(event_type, 0) + 1
            events.append(
                {
                    "time": timestamp_value,
                    "type": event_type,
                    "layer": layer,
                    "artifact": artifact,
                }
            )

    events = [event for event in events if safe_parse(event.get("time"))]
    events.sort(key=lambda event: (safe_parse(event["time"]), event["layer"], event["artifact"], event["type"]))

    summary_parts = []
    for event_type in ("MODIFIED", "CREATED", "ACCESSED"):
        count = type_counts.get(event_type, 0)
        if count:
            summary_parts.append(f"{count} {event_type.lower()}")

    summary_text = f"{len(events)} timeline events reconstructed from artifact timestamps."
    if summary_parts:
        summary_text += " " + ", ".join(summary_parts) + "."

    return {
        "events": events,
        "summary": summary_text,
    }

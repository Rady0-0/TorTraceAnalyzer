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


def build_timeline(all_detections):
    events = []
    seen = set()

    for detection in all_detections:
        timestamps = detection.get("disk_timestamps", {})
        layer = detection.get("layer", "UNKNOWN")
        artifact = detection.get("file_name") or detection.get("artifact") or "UNKNOWN"

        for event_type, key in (
            ("MODIFIED", "modified"),
            ("CREATED", "created"),
            ("ACCESSED", "accessed"),
        ):
            time_value = timestamps.get(key)
            if not safe_parse(time_value):
                continue

            event_key = (time_value, event_type, layer, artifact)
            if event_key in seen:
                continue
            seen.add(event_key)
            events.append(
                {
                    "time": time_value,
                    "type": event_type,
                    "layer": layer,
                    "artifact": artifact,
                }
            )

        modified_dt = safe_parse(timestamps.get("modified"))
        created_dt = safe_parse(timestamps.get("created"))
        if modified_dt and created_dt and created_dt > modified_dt:
            anomaly_key = (timestamps.get("created"), "ANOMALY", layer, artifact)
            if anomaly_key not in seen:
                seen.add(anomaly_key)
                events.append(
                    {
                        "time": timestamps.get("created"),
                        "type": "ANOMALY",
                        "layer": layer,
                        "artifact": artifact,
                        "note": "Possible timestomping (created > modified)",
                    }
                )

    events = [event for event in events if safe_parse(event.get("time"))]
    events.sort(key=lambda event: (safe_parse(event["time"]), event["layer"], event["artifact"], event["type"]))

    return {
        "events": events,
        "summary": f"{len(events)} timeline events reconstructed (MACB format).",
    }

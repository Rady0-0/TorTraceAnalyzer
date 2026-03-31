import matplotlib.pyplot as plt


EVENT_COLORS = {
    "ANOMALY": "#ff6b6b",
    "MODIFIED": "#00d2d3",
    "CREATED": "#20bf6b",
    "ACCESSED": "#feca57",
}


LAYER_COLORS = {
    "Memory": "#ff9f43",
    "System": "#54a0ff",
    "Network": "#5f27cd",
    "Application": "#1dd1a1",
    "Transport": "#f368e0",
}


def build_event_pie_figure(timeline_data):
    events = timeline_data.get("events", [])
    if not events:
        return None

    type_counts = {}
    for event in events:
        event_type = event.get("type", "UNKNOWN")
        type_counts[event_type] = type_counts.get(event_type, 0) + 1

    if not type_counts:
        return None

    figure, axis = plt.subplots(figsize=(8.5, 5.2))
    figure.patch.set_facecolor("#111827")
    axis.set_facecolor("#111827")

    labels = list(type_counts.keys())
    values = list(type_counts.values())
    colors = [EVENT_COLORS.get(label, "#c8d6e5") for label in labels]

    axis.pie(
        values,
        labels=labels,
        colors=colors,
        autopct="%1.1f%%",
        startangle=120,
        textprops={"color": "white"},
    )
    axis.set_title("Event Type Distribution", color="white", fontsize=13)
    figure.tight_layout()
    return figure


def build_detection_pie_figure(detections):
    if not detections:
        return None

    layer_counts = {}
    for detection in detections:
        layer = str(detection.get("layer", "Unknown")).title()
        layer_counts[layer] = layer_counts.get(layer, 0) + 1

    if not layer_counts:
        return None

    labels = list(layer_counts.keys())
    values = list(layer_counts.values())
    colors = [LAYER_COLORS.get(label, "#c8d6e5") for label in labels]

    figure, axis = plt.subplots(figsize=(8.5, 5.2))
    figure.patch.set_facecolor("#111827")
    axis.set_facecolor("#111827")
    axis.pie(
        values,
        labels=[f"{label} ({value})" for label, value in zip(labels, values)],
        colors=colors,
        autopct="%1.1f%%",
        startangle=110,
        textprops={"color": "white"},
    )
    axis.set_title("Detections by Forensic Layer", color="white", fontsize=13)
    figure.tight_layout()
    return figure


def save_event_pie_figure(timeline_data, save_path):
    figure = build_event_pie_figure(timeline_data)
    if figure is None:
        return None
    figure.savefig(save_path, dpi=300, bbox_inches="tight")
    plt.close(figure)
    return save_path


def save_detection_pie_figure(detections, save_path):
    figure = build_detection_pie_figure(detections)
    if figure is None:
        return None
    figure.savefig(save_path, dpi=300, bbox_inches="tight")
    plt.close(figure)
    return save_path

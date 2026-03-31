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

LAYER_ORDER = {
    "System": 0,
    "Application": 1,
    "Network": 2,
    "Transport": 3,
    "Memory": 4,
}

EVENT_ORDER = ["MODIFIED", "CREATED", "ACCESSED", "ANOMALY"]


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


def build_activity_matrix_figure(timeline_data):
    events = timeline_data.get("events", [])
    if not events:
        return None

    layers = sorted(
        {str(event.get("layer", "Unknown")).title() for event in events},
        key=lambda value: (LAYER_ORDER.get(value, 99), value),
    )
    event_types = [event_type for event_type in EVENT_ORDER if any(event.get("type") == event_type for event in events)]

    if not layers or not event_types:
        return None

    matrix = []
    max_value = 0
    for layer in layers:
        row = []
        for event_type in event_types:
            count = sum(
                1
                for event in events
                if str(event.get("layer", "Unknown")).title() == layer and event.get("type") == event_type
            )
            row.append(count)
            max_value = max(max_value, count)
        matrix.append(row)

    figure_width = max(6.2, len(event_types) * 1.5)
    figure_height = max(4.4, len(layers) * 1.2)
    figure, axis = plt.subplots(figsize=(figure_width, figure_height))
    figure.patch.set_facecolor("#111827")
    axis.set_facecolor("#111827")

    image = axis.imshow(matrix, cmap="YlGnBu", aspect="auto", vmin=0, vmax=max(max_value, 1))
    color_bar = figure.colorbar(image, ax=axis, fraction=0.045, pad=0.04)
    color_bar.ax.yaxis.set_tick_params(color="white")
    plt.setp(color_bar.ax.get_yticklabels(), color="white")

    axis.set_xticks(range(len(event_types)))
    axis.set_xticklabels([event_type.title() for event_type in event_types], color="white")
    axis.set_yticks(range(len(layers)))
    axis.set_yticklabels(layers, color="white")
    axis.set_xlabel("Event Type", color="white")
    axis.set_ylabel("Layer", color="white")
    axis.set_title("Artifact Activity Matrix", color="white", fontsize=13)
    axis.tick_params(axis="x", labelrotation=0)

    for row_index, row in enumerate(matrix):
        for col_index, value in enumerate(row):
            text_color = "#0f172a" if value >= (max_value / 2 if max_value else 1) else "white"
            axis.text(col_index, row_index, str(value), ha="center", va="center", color=text_color, fontsize=11, weight="bold")

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


def save_activity_matrix_figure(timeline_data, save_path):
    figure = build_activity_matrix_figure(timeline_data)
    if figure is None:
        return None
    figure.savefig(save_path, dpi=300, bbox_inches="tight")
    plt.close(figure)
    return save_path

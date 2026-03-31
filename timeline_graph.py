from datetime import datetime

import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.lines import Line2D

plt.style.use("dark_background")


EVENT_COLORS = {
    "ANOMALY": "#ff6b6b",
    "MODIFIED": "#00d2d3",
    "CREATED": "#20bf6b",
    "ACCESSED": "#feca57",
}


def _parse_event_time(raw_value):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(raw_value, fmt)
        except (TypeError, ValueError):
            continue
    return None


def build_timeline_figure(timeline_data):
    events = timeline_data.get("events", [])
    if not events:
        return None

    parsed = []
    for event in events:
        event_time = _parse_event_time(event.get("time"))
        if not event_time:
            continue
        parsed.append(
            {
                "time": event_time,
                "layer": event.get("layer", "Unknown"),
                "artifact": event.get("artifact", "Unknown"),
                "type": event.get("type", ""),
            }
        )

    if not parsed:
        return None

    parsed.sort(key=lambda item: item["time"])
    layers = sorted({event["layer"] for event in parsed})
    layer_positions = {layer: index for index, layer in enumerate(layers)}

    figure, axis = plt.subplots(figsize=(10, 5.5))
    figure.patch.set_facecolor("#111827")
    axis.set_facecolor("#111827")

    for event in parsed:
        color = EVENT_COLORS.get(event["type"], "white")
        axis.scatter(event["time"], layer_positions[event["layer"]], c=color, s=65, edgecolors="none")

    axis.set_yticks(list(layer_positions.values()))
    axis.set_yticklabels(list(layer_positions.keys()))
    axis.set_xlabel("Time")
    axis.set_title("Forensic Timeline (MACB)")
    axis.grid(True, linestyle="--", linewidth=0.4, alpha=0.35)

    legend_handles = [
        Line2D([0], [0], marker="o", color="none", markerfacecolor=color, markersize=8, label=label.title())
        for label, color in EVENT_COLORS.items()
    ]
    axis.legend(handles=legend_handles, loc="upper right", frameon=False)
    figure.tight_layout()
    return figure


def plot_timeline_embedded(timeline_data, frame):
    figure = build_timeline_figure(timeline_data)
    if figure is None:
        return None

    for widget in frame.winfo_children():
        widget.destroy()

    canvas = FigureCanvasTkAgg(figure, master=frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)
    return canvas


def plot_timeline(timeline_data, save_path=None):
    figure = build_timeline_figure(timeline_data)
    if figure is None:
        return None

    if save_path:
        figure.savefig(save_path, dpi=300, bbox_inches="tight")
        plt.close(figure)
        return save_path

    plt.show()
    plt.close(figure)
    return None

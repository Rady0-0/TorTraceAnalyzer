from datetime import datetime

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
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
        artifact = event.get("artifact", "Unknown")
        label = f"{event.get('layer', 'Unknown')}: {artifact}"
        if len(label) > 52:
            label = label[:49] + "..."
        parsed.append(
            {
                "time": event_time,
                "layer": event.get("layer", "Unknown"),
                "artifact": artifact,
                "label": label,
                "type": event.get("type", ""),
            }
        )

    if not parsed:
        return None

    parsed.sort(key=lambda item: item["time"])
    labels = []
    for event in parsed:
        if event["label"] not in labels:
            labels.append(event["label"])
    label_positions = {label: index for index, label in enumerate(labels)}

    figure, axis = plt.subplots(figsize=(11.8, 4.9))
    figure.patch.set_facecolor("#111827")
    axis.set_facecolor("#111827")

    time_values = [mdates.date2num(event["time"]) for event in parsed]
    min_time = min(time_values)
    max_time = max(time_values)
    span = max(max_time - min_time, 1 / (24 * 60))
    bar_width = max(span * 0.04, 20 / (24 * 60))

    for event in parsed:
        color = EVENT_COLORS.get(event["type"], "white")
        event_num = mdates.date2num(event["time"])
        left = event_num - (bar_width / 2)
        axis.barh(
            label_positions[event["label"]],
            width=bar_width,
            left=left,
            height=0.58,
            color=color,
            alpha=0.9,
            edgecolor="none",
        )

    axis.set_yticks(list(label_positions.values()))
    axis.set_yticklabels(list(label_positions.keys()))
    axis.set_xlabel("Artifact Timestamp")
    axis.set_title("Artifact Timeline (Horizontal Event Bars)")
    axis.grid(True, axis="x", linestyle="--", linewidth=0.4, alpha=0.28)
    axis.xaxis.set_major_locator(mdates.AutoDateLocator(minticks=4, maxticks=8))
    axis.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d\n%H:%M"))
    axis.tick_params(axis="x", labelsize=9)
    axis.tick_params(axis="y", labelsize=9)
    axis.invert_yaxis()

    legend_handles = [
        Line2D([0], [0], color=color, linewidth=8, label=label.title())
        for label, color in EVENT_COLORS.items()
    ]
    axis.legend(handles=legend_handles, loc="upper right", frameon=False)
    figure.tight_layout(pad=1.4)
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

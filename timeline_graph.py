import matplotlib.pyplot as plt
plt.style.use("dark_background")
from datetime import datetime


def _build_timeline_figure(timeline_data):
    events = timeline_data.get("events", [])

    if not events:
        return None

    parsed = []
    for e in events:
        try:
            t = datetime.strptime(e["time"], "%Y-%m-%d %H:%M:%S")
            parsed.append({
                "time": t,
                "layer": e.get("layer", "Unknown"),
                "artifact": e.get("artifact", "Unknown"),
                "type": e.get("type", "")
            })
        except:
            continue

    if not parsed:
        return None

    parsed.sort(key=lambda x: x["time"])

    layers = sorted(set(e["layer"] for e in parsed))
    layer_y = {layer: i for i, layer in enumerate(layers)}

    def get_color(t):
        return {
            "ANOMALY": "red",
            "MODIFIED": "cyan",
            "CREATED": "green",
            "ACCESSED": "yellow"
        }.get(t, "white")

    fig, ax = plt.subplots(figsize=(10, 4))

    for e in parsed:
        ax.scatter(e["time"], layer_y[e["layer"]], c=get_color(e["type"]), s=60)

    ax.set_yticks(list(layer_y.values()))
    ax.set_yticklabels(list(layer_y.keys()))
    ax.set_xlabel("Time")
    ax.set_title("Forensic Timeline (MACB)")
    ax.grid(True)

    return fig


def plot_timeline_embedded(timeline_data, frame):
    fig = _build_timeline_figure(timeline_data)
    if fig is None:
        return

    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

    for widget in frame.winfo_children():
        widget.destroy()

    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)


def plot_timeline(timeline_data, save_path=None):
    fig = _build_timeline_figure(timeline_data)
    if fig is None:
        return

    if save_path:
        fig.savefig(save_path, dpi=300, bbox_inches='tight')
    else:
        plt.show()
    plt.close(fig)

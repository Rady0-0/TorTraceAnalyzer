import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


LAYER_COLOR = "#2f6fed"
ARTIFACT_COLOR = "#20bf6b"
EDGE_COLOR = "#9aa5b1"


def build_relationship_figure(detections):
    if not detections:
        return None

    graph = nx.Graph()
    for detection in detections:
        artifact = detection.get("file_name") or detection.get("artifact") or "Unknown"
        layer = detection.get("layer", "Unknown")
        graph.add_node(layer, type="layer")
        graph.add_node(artifact, type="artifact")
        graph.add_edge(layer, artifact)

    layer_nodes = sorted(node for node, data in graph.nodes(data=True) if data.get("type") == "layer")
    artifact_nodes = sorted(node for node, data in graph.nodes(data=True) if data.get("type") == "artifact")

    positions = {}
    layer_count = max(len(layer_nodes), 1)
    artifact_count = max(len(artifact_nodes), 1)

    for index, node in enumerate(layer_nodes):
        y_pos = 1 - (index / max(layer_count - 1, 1)) if layer_count > 1 else 0.5
        positions[node] = (0.15, y_pos)

    for index, node in enumerate(artifact_nodes):
        y_pos = 1 - (index / max(artifact_count - 1, 1)) if artifact_count > 1 else 0.5
        positions[node] = (0.85, y_pos)

    figure, axis = plt.subplots(figsize=(9, 5.5))
    figure.patch.set_facecolor("#111827")
    axis.set_facecolor("#111827")

    nx.draw_networkx_nodes(graph, positions, nodelist=layer_nodes, node_color=LAYER_COLOR, node_size=2600, ax=axis)
    nx.draw_networkx_nodes(graph, positions, nodelist=artifact_nodes, node_color=ARTIFACT_COLOR, node_size=2100, ax=axis)
    nx.draw_networkx_edges(graph, positions, ax=axis, width=1.3, alpha=0.8, edge_color=EDGE_COLOR)
    nx.draw_networkx_labels(graph, positions, ax=axis, font_size=8, font_color="white")

    axis.set_title("Artifact Relationship Map", color="white", fontsize=13)
    axis.text(0.15, 1.04, "Forensic Layers", color="#bcd3ff", fontsize=10, fontweight="bold", ha="center", transform=axis.transAxes)
    axis.text(0.85, 1.04, "Detected Artifacts", color="#bbf7d0", fontsize=10, fontweight="bold", ha="center", transform=axis.transAxes)
    axis.axis("off")
    figure.tight_layout()
    return figure


def plot_relationship(detections):
    figure = build_relationship_figure(detections)
    if figure is None:
        return
    plt.show()
    plt.close(figure)


def plot_relationship_embedded(detections, frame):
    figure = build_relationship_figure(detections)
    if figure is None:
        return None

    for widget in frame.winfo_children():
        widget.destroy()

    canvas = FigureCanvasTkAgg(figure, master=frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)
    return canvas


def save_relationship_figure(detections, save_path):
    figure = build_relationship_figure(detections)
    if figure is None:
        return None
    figure.savefig(save_path, dpi=300, bbox_inches="tight")
    plt.close(figure)
    return save_path

import matplotlib.pyplot as plt
import networkx as nx


def _build_relationship_figure(detections):
    if not detections:
        return None

    graph = nx.Graph()

    for detection in detections:
        artifact = detection.get("file_name") or detection.get("artifact") or "Unknown"
        layer = detection.get("layer", "Unknown")

        graph.add_node(artifact, type="artifact")
        graph.add_node(layer, type="layer")
        graph.add_edge(layer, artifact)

    positions = nx.spring_layout(graph, seed=42)
    figure, axis = plt.subplots(figsize=(8, 4))

    layer_nodes = [node for node, data in graph.nodes(data=True) if data.get("type") == "layer"]
    artifact_nodes = [node for node, data in graph.nodes(data=True) if data.get("type") == "artifact"]

    nx.draw_networkx_nodes(graph, positions, nodelist=layer_nodes, node_color="#1f77b4", node_size=2200, ax=axis)
    nx.draw_networkx_nodes(graph, positions, nodelist=artifact_nodes, node_color="#2ca02c", node_size=1800, ax=axis)
    nx.draw_networkx_edges(graph, positions, ax=axis, width=1.2, alpha=0.7)
    nx.draw_networkx_labels(graph, positions, ax=axis, font_size=8, font_color="white")

    axis.set_title("Artifact Relationship Map")
    axis.axis("off")
    figure.tight_layout()
    return figure


def plot_relationship(detections):
    figure = _build_relationship_figure(detections)
    if figure is None:
        return
    plt.show()
    plt.close(figure)


def plot_relationship_embedded(detections, frame):
    figure = _build_relationship_figure(detections)
    if figure is None:
        return

    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

    for widget in frame.winfo_children():
        widget.destroy()

    canvas = FigureCanvasTkAgg(figure, master=frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)

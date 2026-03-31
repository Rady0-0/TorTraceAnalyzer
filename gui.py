import os
import multiprocessing as mp
import queue
import time
import traceback
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox
from tkinter import ttk

import customtkinter as ctk
from PIL import Image
from matplotlib import pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from app_paths import get_temp_graph_path, resource_path
from case_manager import get_case_by_name, get_case_names, save_case
from relation_graph import build_relationship_figure, save_relationship_figure
from visualization_utils import (
    build_activity_matrix_figure,
    build_detection_pie_figure,
    save_activity_matrix_figure,
    save_detection_pie_figure,
)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

CASE_FIELDS = [
    ("case_name", "Case Name"),
    ("case_id", "Case ID"),
    ("investigator", "Investigator"),
    ("organization", "Organization"),
    ("department", "Department"),
    ("contact_email", "Contact Email"),
    ("case_description", "Description"),
]


def run_analysis_process(selected_paths, case_info, output_queue):
    try:
        from main import run_analysis

        def event_callback(event):
            output_queue.put(event)

        result = run_analysis(selected_paths, event_callback=event_callback, case_info=case_info)
        output_queue.put({"type": "complete", "result": result})
    except Exception as exc:
        output_queue.put({"type": "worker_error", "message": str(exc), "traceback": traceback.format_exc()})


class TorTraceGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.title("TorTrace Analyzer")
        self.geometry("1520x940")
        self.minsize(1300, 840)
        self._set_window_icon()

        self.test_mode = os.environ.get("TORTRACE_TEST_MODE") == "1"
        self.startup_complete = False
        self.case_info = self._default_case_info()
        self.analysis_process = None
        self.mp_context = mp.get_context("spawn")
        self.analysis_aborted = False
        self.current_figure = None
        self.graph_canvas = None
        self.correlation_items = []
        self.timer_after_id = None
        self.queue_after_id = None
        self.startup_after_id = None

        self.selected_paths = []
        self.timeline_data = {}
        self.analysis_running = False
        self.start_time = None
        self.smart_mode = False
        self.all_findings = []
        self.all_detections = []
        self.fci_score = 0.0
        self.determination = ""
        self.correlation_summary = ""
        self.report_path = ""
        self.dashboard_messages = []
        self.output_queue = queue.Queue()

        self.current_file = tk.StringVar(value="Current file: Waiting to start")
        self.status = tk.StringVar(value="READY")
        self.timer = tk.StringVar(value="Elapsed: 0s")
        self.case_summary = tk.StringVar(value="No case loaded")
        self.timeline_summary = tk.StringVar(value="Timeline table is empty.")

        self.layer_data = {"memory": [], "system": [], "network": [], "application": [], "transport": []}
        self.latest_layer_results = {layer: [] for layer in self.layer_data}
        self.latest_evidence_files = []
        self.layer_tables = {}
        self.layer_detail_boxes = {}
        self.layer_summary_vars = {}
        self.table_style_configured = False

        self.logo_image_large = self._load_logo((92, 92))
        self.logo_image_small = self._load_logo((54, 54))

        self.build_ui()
        self._refresh_case_menu()
        self._update_case_summary()

        if self.test_mode:
            self.startup_complete = True
        else:
            self.withdraw()
            self.startup_after_id = self.after(120, self._start_splash_sequence)

    def _default_case_info(self):
        return {
            "case_name": "New Case",
            "case_id": f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "investigator": "",
            "organization": "",
            "department": "",
            "contact_email": "",
            "case_description": "",
        }

    def _set_window_icon(self):
        icon_path = resource_path(os.path.join("assets", "tortrace_icon_v2.ico"))
        if os.path.exists(icon_path):
            try:
                self.iconbitmap(icon_path)
            except Exception:
                pass

    def _load_logo(self, size):
        logo_path = resource_path(os.path.join("assets", "tortrace_logo_v2.png"))
        if not os.path.exists(logo_path):
            return None
        try:
            with Image.open(logo_path) as image:
                return ctk.CTkImage(light_image=image.copy(), dark_image=image.copy(), size=size)
        except Exception:
            return None

    def build_ui(self):
        header = ctk.CTkFrame(self, corner_radius=16)
        header.pack(fill="x", padx=18, pady=(16, 8))
        brand = ctk.CTkFrame(header, fg_color="transparent")
        brand.pack(side="left", fill="x", expand=True, padx=16, pady=12)
        if self.logo_image_small:
            ctk.CTkLabel(brand, image=self.logo_image_small, text="").pack(side="left", padx=(0, 12))
        brand_text = ctk.CTkFrame(brand, fg_color="transparent")
        brand_text.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(brand_text, text="TOR TRACE ANALYZER", font=ctk.CTkFont(size=28, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(
            brand_text,
            text="Multi-layer forensic analysis for Tor-related evidence",
            text_color="#a5b1c2",
        ).pack(anchor="w", pady=(4, 0))
        self.case_badge = ctk.CTkLabel(header, textvariable=self.case_summary, justify="right", font=ctk.CTkFont(size=13, weight="bold"), text_color="#dfe6e9")
        self.case_badge.pack(side="right", padx=18, pady=16)

        self.control_shell = ctk.CTkFrame(self, corner_radius=16)
        self.control_shell.pack(fill="x", padx=18, pady=(0, 8))
        self.controls_container = ctk.CTkTabview(self.control_shell, corner_radius=14, height=138)
        self.controls_container.pack(fill="x", padx=12, pady=10)
        self._build_control_frames()

        action_frame = ctk.CTkFrame(self, corner_radius=16)
        action_frame.pack(fill="x", padx=18, pady=(0, 8))
        self.path_entry = ctk.CTkEntry(action_frame, placeholder_text="Choose individual evidence files or an evidence folder")
        self.path_entry.pack(side="left", fill="x", expand=True, padx=12, pady=10)
        self.files_button = ctk.CTkButton(action_frame, text="Files", command=self.add_files, width=110)
        self.files_button.pack(side="left", padx=(0, 8), pady=10)
        self.folder_button = ctk.CTkButton(action_frame, text="Folder", command=self.add_folder, width=110)
        self.folder_button.pack(side="left", padx=(0, 8), pady=10)
        self.run_button = ctk.CTkButton(action_frame, text="Run Analysis", command=self.start_analysis, width=140, fg_color="#1f8b4c", hover_color="#176d3c")
        self.run_button.pack(side="left", padx=(0, 8), pady=10)
        self.abort_button = ctk.CTkButton(
            action_frame,
            text="Abort",
            command=self.abort_analysis,
            width=110,
            fg_color="#b33939",
            hover_color="#8c2c2c",
            state="disabled",
        )
        self.abort_button.pack(side="left", padx=(0, 12), pady=10)

        status_card = ctk.CTkFrame(self, corner_radius=16)
        status_card.pack(fill="x", padx=18, pady=(0, 8))
        self.progress = ctk.CTkProgressBar(status_card)
        self.progress.pack(fill="x", padx=14, pady=(12, 8))
        self.progress.set(0)
        status_row = ctk.CTkFrame(status_card, fg_color="transparent")
        status_row.pack(fill="x", padx=14, pady=(0, 10))
        ctk.CTkLabel(status_row, textvariable=self.status, text_color="#e6edf3").pack(side="left", padx=(0, 20))
        ctk.CTkLabel(status_row, textvariable=self.timer, text_color="#a5b1c2").pack(side="left", padx=(0, 20))
        ctk.CTkLabel(status_row, textvariable=self.current_file, text_color="#1dd1a1").pack(side="left")
        workspace = ctk.CTkFrame(self, fg_color="transparent")
        workspace.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        left_panel = ctk.CTkFrame(workspace, corner_radius=16)
        left_panel.pack(side="left", fill="both", expand=True)
        right_panel = ctk.CTkFrame(workspace, corner_radius=16, width=540)
        right_panel.pack(side="right", fill="both", padx=(12, 0))
        right_panel.pack_propagate(False)

        self.tabs = {}
        self.tabview = ctk.CTkTabview(left_panel)
        self.tabview.pack(fill="both", expand=True, padx=12, pady=12)
        dashboard_tab = self.tabview.add("DASHBOARD")
        dashboard_text = tk.Text(
            dashboard_tab,
            bg="#0f172a",
            fg="#e2e8f0",
            insertbackground="white",
            font=("Consolas", 11),
            wrap="word",
            relief="flat",
            borderwidth=0,
            padx=10,
            pady=10,
        )
        dashboard_text.pack(fill="both", expand=True)
        dashboard_text.bind("<Button-1>", self.on_artifact_click)
        self.tabs["dashboard"] = dashboard_text

        self._configure_treeview_styles()
        for name in ["memory", "system", "network", "application", "transport"]:
            tab = self.tabview.add(name.upper())
            self._build_layer_tab(tab, name)
        for tab in self.tabs.values():
            tab.tag_config("critical", foreground="#ff6b6b", font=("Consolas", 11, "bold"))
            tab.tag_config("high", foreground="#ffb84d")
            tab.tag_config("medium", foreground="#4dd0e1")
            tab.tag_config("artifact", foreground="#40e0a0")
            tab.tag_config("normal", foreground="#e2e8f0")
            tab.tag_config("muted", foreground="#94a3b8")
        self.output = self.tabs["dashboard"]

        timeline_tab = self.tabview.add("TIMELINE")
        self._build_timeline_tab(timeline_tab)

        self.side_workspace = ctk.CTkTabview(right_panel)
        self.side_workspace.pack(fill="both", expand=True, padx=14, pady=14)
        visuals_tab = self.side_workspace.add("VISUALS")
        notes_tab = self.side_workspace.add("NOTES")

        visual_header = ctk.CTkFrame(visuals_tab, fg_color="transparent")
        visual_header.pack(fill="x", padx=8, pady=(8, 8))
        ctk.CTkLabel(visual_header, text="Visual Evidence Panel", font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w")
        self.graph_label = ctk.CTkLabel(visual_header, text="No visual selected", font=ctk.CTkFont(size=13, weight="bold"), text_color="#cbd5e1")
        self.graph_label.pack(anchor="w", pady=(4, 0))
        self.graph_canvas_frame = ctk.CTkFrame(visuals_tab, corner_radius=14)
        self.graph_canvas_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        ctk.CTkLabel(notes_tab, text="Investigator Notes", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=10, pady=(10, 8))
        self.notes_box = ctk.CTkTextbox(notes_tab)
        self.notes_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.notes_box.insert("1.0", "Investigator notes and conclusions...")
        self.side_workspace.set("VISUALS")
        self._show_visual_placeholder("Run analysis and choose a visual.")

    def _configure_treeview_styles(self):
        if self.table_style_configured:
            return

        self.table_style_configured = True
        self.timeline_style = ttk.Style()
        try:
            self.timeline_style.theme_use("clam")
        except Exception:
            pass

        self.timeline_style.configure(
            "TorTrace.Treeview",
            background="#0f172a",
            foreground="#e2e8f0",
            fieldbackground="#0f172a",
            borderwidth=0,
            rowheight=28,
            font=("Segoe UI", 10),
        )
        self.timeline_style.configure(
            "TorTrace.Treeview.Heading",
            background="#1f2937",
            foreground="#f8fafc",
            relief="flat",
            font=("Segoe UI", 10, "bold"),
        )
        self.timeline_style.map(
            "TorTrace.Treeview",
            background=[("selected", "#1d4ed8")],
            foreground=[("selected", "#f8fafc")],
        )

    def _build_layer_tab(self, layer_tab, layer_key):
        shell = ctk.CTkFrame(layer_tab, fg_color="transparent")
        shell.pack(fill="both", expand=True, padx=10, pady=10)

        header = ctk.CTkFrame(shell, fg_color="transparent")
        header.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(
            header,
            text=f"{layer_key.title()} Evidence Table",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(anchor="w")
        summary_var = tk.StringVar(value=f"No {layer_key} detections loaded.")
        self.layer_summary_vars[layer_key] = summary_var
        ctk.CTkLabel(
            header,
            textvariable=summary_var,
            text_color="#9fb2c3",
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

        table_shell = ctk.CTkFrame(shell, corner_radius=12)
        table_shell.pack(fill="both", expand=True)

        table = ttk.Treeview(
            table_shell,
            style="TorTrace.Treeview",
            columns=("artifact", "status", "evidence", "path"),
            show="headings",
            selectmode="browse",
        )
        table.heading("artifact", text="Artifact")
        table.heading("status", text="Status")
        table.heading("evidence", text="Evidence")
        table.heading("path", text=self._layer_location_heading(layer_key))
        table.column("artifact", width=230, anchor="w")
        table.column("status", width=100, anchor="center")
        table.column("evidence", width=220, anchor="w")
        table.column("path", width=520, anchor="w")

        scroll_y = ttk.Scrollbar(table_shell, orient="vertical", command=table.yview)
        scroll_x = ttk.Scrollbar(table_shell, orient="horizontal", command=table.xview)
        table.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

        table.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")
        table_shell.grid_rowconfigure(0, weight=1)
        table_shell.grid_columnconfigure(0, weight=1)

        table.tag_configure("detected", foreground="#40e0a0")
        table.tag_configure("suspicious", foreground="#ffb84d")
        table.tag_configure("critical", foreground="#ff6b6b")
        table.bind("<<TreeviewSelect>>", lambda _event, layer=layer_key: self._on_layer_select(layer))

        details_shell = ctk.CTkFrame(shell, corner_radius=12)
        details_shell.pack(fill="x", pady=(10, 0))
        ctk.CTkLabel(
            details_shell,
            text="Selected Artifact Details",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(10, 6))
        detail_box = ctk.CTkTextbox(details_shell, height=140)
        detail_box.pack(fill="x", padx=12, pady=(0, 12))
        detail_box.insert("1.0", "Select a row to inspect the full detection details.")
        detail_box.configure(state="disabled")

        self.layer_tables[layer_key] = table
        self.layer_detail_boxes[layer_key] = detail_box

    def _build_timeline_tab(self, timeline_tab):
        timeline_shell = ctk.CTkFrame(timeline_tab, fg_color="transparent")
        timeline_shell.pack(fill="both", expand=True, padx=10, pady=10)

        timeline_header = ctk.CTkFrame(timeline_shell, fg_color="transparent")
        timeline_header.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(
            timeline_header,
            text="Timeline Evidence Table",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(anchor="w")
        ctk.CTkLabel(
            timeline_header,
            textvariable=self.timeline_summary,
            text_color="#9fb2c3",
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

        table_shell = ctk.CTkFrame(timeline_shell, corner_radius=12)
        table_shell.pack(fill="both", expand=True)

        self.timeline_table = ttk.Treeview(
            table_shell,
            style="TorTrace.Treeview",
            columns=("time", "event", "layer", "artifact"),
            show="headings",
            selectmode="browse",
        )
        self.timeline_table.heading("time", text="Timestamp")
        self.timeline_table.heading("event", text="Event")
        self.timeline_table.heading("layer", text="Layer")
        self.timeline_table.heading("artifact", text="Artifact")
        self.timeline_table.column("time", width=190, anchor="w")
        self.timeline_table.column("event", width=110, anchor="center")
        self.timeline_table.column("layer", width=110, anchor="center")
        self.timeline_table.column("artifact", width=520, anchor="w")

        timeline_scroll_y = ttk.Scrollbar(table_shell, orient="vertical", command=self.timeline_table.yview)
        timeline_scroll_x = ttk.Scrollbar(table_shell, orient="horizontal", command=self.timeline_table.xview)
        self.timeline_table.configure(yscrollcommand=timeline_scroll_y.set, xscrollcommand=timeline_scroll_x.set)

        self.timeline_table.grid(row=0, column=0, sticky="nsew")
        timeline_scroll_y.grid(row=0, column=1, sticky="ns")
        timeline_scroll_x.grid(row=1, column=0, sticky="ew")
        table_shell.grid_rowconfigure(0, weight=1)
        table_shell.grid_columnconfigure(0, weight=1)

        self.timeline_table.tag_configure("modified", background="#0f172a", foreground="#4dd0e1")
        self.timeline_table.tag_configure("created", background="#0f172a", foreground="#40e0a0")
        self.timeline_table.tag_configure("accessed", background="#0f172a", foreground="#ffb84d")
        self.timeline_table.tag_configure("anomaly", background="#0f172a", foreground="#ff6b6b")
        self.timeline_table.bind("<<TreeviewSelect>>", self._on_timeline_select)

        details_shell = ctk.CTkFrame(timeline_shell, corner_radius=12)
        details_shell.pack(fill="x", pady=(10, 0))
        ctk.CTkLabel(
            details_shell,
            text="Selected Event Details",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(10, 6))
        self.timeline_detail_box = ctk.CTkTextbox(details_shell, height=130)
        self.timeline_detail_box.pack(fill="x", padx=12, pady=(0, 12))
        self._set_timeline_detail("Select a timeline row to inspect its artifact details.")

    def _set_timeline_detail(self, text):
        self.timeline_detail_box.configure(state="normal")
        self.timeline_detail_box.delete("1.0", tk.END)
        self.timeline_detail_box.insert("1.0", text)
        self.timeline_detail_box.configure(state="disabled")

    def _clear_timeline_table(self, message="Timeline table is empty."):
        if hasattr(self, "timeline_table"):
            for item_id in self.timeline_table.get_children():
                self.timeline_table.delete(item_id)
        self.timeline_summary.set(message)
        if hasattr(self, "timeline_detail_box"):
            self._set_timeline_detail("Select a timeline row to inspect its artifact details.")

    def _set_layer_detail(self, layer_key, text):
        detail_box = self.layer_detail_boxes.get(layer_key)
        if detail_box is None:
            return
        detail_box.configure(state="normal")
        detail_box.delete("1.0", tk.END)
        detail_box.insert("1.0", text)
        detail_box.configure(state="disabled")

    def _clear_layer_tables(self):
        for layer, table in self.layer_tables.items():
            for item_id in table.get_children():
                table.delete(item_id)
            if layer in self.layer_summary_vars:
                self.layer_summary_vars[layer].set(f"No {layer} detections loaded.")
            self._set_layer_detail(layer, "Select a row to inspect the full detection details.")

    def _layer_row_tag(self, detection):
        status = str(detection.get("status", "")).lower()
        if status == "suspicious":
            return "suspicious"
        if "critical" in str(detection.get("message", "")).lower():
            return "critical"
        return "detected"

    def _layer_location_heading(self, layer_key):
        if str(layer_key).strip().lower() == "transport":
            return "Data Exchange"
        return "Path"

    def _layer_location_text(self, layer_key, detection):
        raw_value = str(detection.get("file_path", "N/A"))
        if str(layer_key).strip().lower() != "transport":
            return raw_value
        if "->" in raw_value:
            return raw_value.replace(" -> ", " <-> ")
        if raw_value.lower().endswith((".pcap", ".pcapng")):
            return "Capture-wide Tor flow summary"
        return raw_value

    def _layer_row_values(self, detection):
        layer_key = str(detection.get("layer", "")).strip().lower()
        return (
            detection.get("file_name", "UNKNOWN"),
            detection.get("status", "Detected"),
            detection.get("evidence_match", "N/A"),
            self._layer_location_text(layer_key, detection),
        )

    def _layer_search_text(self, detection):
        timestamps = detection.get("disk_timestamps", {})
        parts = [
            detection.get("file_name", ""),
            detection.get("status", ""),
            detection.get("evidence_match", ""),
            detection.get("file_path", ""),
            detection.get("message", ""),
        ]
        if self._layer_shows_timestamps(detection.get("layer", "")):
            parts.extend(
                [
                    timestamps.get("modified", ""),
                    timestamps.get("created", ""),
                    timestamps.get("accessed", ""),
                ]
            )
        return " ".join(str(part) for part in parts if part)

    def _layer_shows_timestamps(self, layer_key):
        return str(layer_key).strip().lower() in {"system", "application", "memory"}

    def _find_layer_detection(self, layer_key, keyword):
        query = str(keyword).strip().lower()
        if not query:
            return None
        for entry in self.layer_data.get(layer_key, []):
            haystack = entry.get("search_text", "").lower()
            artifact = str(entry.get("detection", {}).get("file_name", "")).lower()
            if query in haystack or haystack in query or query in artifact or artifact in query:
                return entry
        return None

    def _on_layer_select(self, layer_key):
        table = self.layer_tables.get(layer_key)
        if table is None:
            return
        selection = table.selection()
        if not selection:
            return
        item_id = selection[0]
        detection = None
        for entry in self.layer_data.get(layer_key, []):
            if entry.get("item_id") == item_id:
                detection = entry.get("detection")
                break
        if not detection:
            self._set_layer_detail(layer_key, "Select a row to inspect the full detection details.")
            return

        timestamps = detection.get("disk_timestamps", {})
        lines = [
            f"Artifact : {detection.get('file_name', 'UNKNOWN')}",
            f"Status   : {detection.get('status', 'Detected')}",
            f"Layer    : {detection.get('layer', layer_key.title())}",
            f"{self._layer_location_heading(layer_key):<9}: {self._layer_location_text(layer_key, detection)}",
            f"Evidence : {detection.get('evidence_match', 'N/A')}",
            f"Message  : {detection.get('message', 'N/A')}",
        ]
        if self._layer_shows_timestamps(layer_key):
            lines.extend(
                [
                    f"Modified : {timestamps.get('modified', 'N/A')}",
                    f"Created  : {timestamps.get('created', 'N/A')}",
                    f"Accessed : {timestamps.get('accessed', 'N/A')}",
                ]
            )
        self._set_layer_detail(layer_key, "\n".join(lines))

    def _timeline_row_tag(self, event_type):
        return {
            "MODIFIED": "modified",
            "CREATED": "created",
            "ACCESSED": "accessed",
            "ANOMALY": "anomaly",
        }.get(str(event_type).upper(), "")

    def _find_detection_for_timeline_event(self, event):
        event_layer = str(event.get("layer", "")).title()
        event_artifact = str(event.get("artifact", ""))
        event_time = event.get("time")

        for detection in self.all_detections:
            layer = str(detection.get("layer", "")).title()
            artifact = str(detection.get("file_name") or detection.get("artifact") or "")
            timestamps = detection.get("disk_timestamps", {})
            if layer != event_layer or artifact != event_artifact:
                continue
            if event.get("type") == "MODIFIED" and timestamps.get("modified") == event_time:
                return detection
            if event.get("type") == "CREATED" and timestamps.get("created") == event_time:
                return detection
            if event.get("type") == "ACCESSED" and timestamps.get("accessed") == event_time:
                return detection
        return None

    def _on_timeline_select(self, _event=None):
        selection = self.timeline_table.selection()
        if not selection:
            return

        item_id = selection[0]
        event = self.timeline_table.item(item_id, "values")
        if not event or len(event) < 4:
            return

        event_payload = {
            "time": event[0],
            "type": event[1],
            "layer": event[2],
            "artifact": event[3],
        }
        detection = self._find_detection_for_timeline_event(event_payload)

        lines = [
            f"Timestamp : {event_payload['time']}",
            f"Event     : {event_payload['type']}",
            f"Layer     : {event_payload['layer']}",
            f"Artifact  : {event_payload['artifact']}",
        ]

        if detection:
            timestamps = detection.get("disk_timestamps", {})
            lines.extend(
                [
                    f"Path      : {detection.get('file_path', 'N/A')}",
                    f"Evidence  : {detection.get('evidence_match', 'N/A')}",
                    f"Modified  : {timestamps.get('modified', 'N/A')}",
                    f"Created   : {timestamps.get('created', 'N/A')}",
                    f"Accessed  : {timestamps.get('accessed', 'N/A')}",
                    f"Note      : {detection.get('message', 'N/A')}",
                ]
            )

        self._set_timeline_detail("\n".join(lines))

    def _cancel_after_callback(self, attr_name):
        after_id = getattr(self, attr_name, None)
        if after_id:
            try:
                self.after_cancel(after_id)
            except Exception:
                pass
        setattr(self, attr_name, None)

    def _build_control_frames(self):
        self.search_var = tk.StringVar()
        self.filter_var = tk.StringVar(value="ALL")

        case_frame = self.controls_container.add("CASE")
        case_row_1 = ctk.CTkFrame(case_frame, fg_color="transparent")
        case_row_1.pack(fill="x", padx=12, pady=(10, 8))
        self.case_select = ctk.CTkOptionMenu(case_row_1, values=get_case_names() or ["No Cases"], command=self.load_selected_case, width=180)
        self.case_select.pack(side="left", padx=(0, 8))
        self.manage_case_button = ctk.CTkButton(case_row_1, text="Manage Case", command=self.show_case_manager, width=105)
        self.manage_case_button.pack(side="left")
        case_row_2 = ctk.CTkFrame(case_frame, fg_color="transparent")
        case_row_2.pack(fill="x", padx=12, pady=(0, 10))
        self.search_entry = ctk.CTkEntry(case_row_2, textvariable=self.search_var, placeholder_text="Search current results")
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.search_button = ctk.CTkButton(case_row_2, text="Search", command=self.search_text, width=88)
        self.search_button.pack(side="left")

        timeline_frame = self.controls_container.add("TIMELINE")
        timeline_row_1 = ctk.CTkFrame(timeline_frame, fg_color="transparent")
        timeline_row_1.pack(fill="x", padx=12, pady=(10, 8))
        self.start_date = ctk.CTkEntry(timeline_row_1, width=130, placeholder_text="From YYYY-MM-DD")
        self.start_date.pack(side="left", padx=(0, 8))
        self.end_date = ctk.CTkEntry(timeline_row_1, width=130, placeholder_text="To YYYY-MM-DD")
        self.end_date.pack(side="left", padx=(0, 8))
        self.filter_menu = ctk.CTkOptionMenu(timeline_row_1, values=["ALL", "MODIFIED", "CREATED", "ACCESSED"], variable=self.filter_var, command=lambda _value: self.show_timeline(), width=120)
        self.filter_menu.pack(side="left")
        timeline_row_2 = ctk.CTkFrame(timeline_frame, fg_color="transparent")
        timeline_row_2.pack(fill="x", padx=12, pady=(0, 8))
        self.smart_btn = ctk.CTkButton(timeline_row_2, text="Recent Focus: Off", command=self.toggle_smart, width=130)
        self.smart_btn.pack(side="left", padx=(0, 8))
        self.timeline_refresh_button = ctk.CTkButton(timeline_row_2, text="Refresh Timeline", command=self.show_timeline, width=120)
        self.timeline_refresh_button.pack(side="left")

        visual_frame = self.controls_container.add("VISUALS")
        visual_row_1 = ctk.CTkFrame(visual_frame, fg_color="transparent")
        visual_row_1.pack(fill="x", padx=12, pady=(10, 8))
        self.activity_matrix_button = ctk.CTkButton(visual_row_1, text="Activity Matrix", command=self.show_activity_matrix, width=120)
        self.activity_matrix_button.pack(side="left", padx=(0, 8))
        self.event_pie_button = ctk.CTkButton(visual_row_1, text="Evidence Pie", command=self.show_pie_chart, width=105)
        self.event_pie_button.pack(side="left", padx=(0, 8))
        self.relation_button = ctk.CTkButton(visual_row_1, text="Relations", command=self.show_relation, width=95)
        self.relation_button.pack(side="left")
        visual_row_2 = ctk.CTkFrame(visual_frame, fg_color="transparent")
        visual_row_2.pack(fill="x", padx=12, pady=(0, 8))
        self.format_menu = ctk.CTkComboBox(visual_row_2, values=["TXT", "CSV", "EXCEL", "JSON", "PDF"], width=110)
        self.format_menu.set("PDF")
        self.format_menu.pack(side="left", padx=(0, 8))
        self.export_button = ctk.CTkButton(visual_row_2, text="Export Report", command=self.export, width=120)
        self.export_button.pack(side="left")
    def _start_splash_sequence(self):
        splash = ctk.CTkToplevel(self)
        splash.overrideredirect(True)
        splash.configure(fg_color="#08111f")
        splash.attributes("-topmost", True)
        splash.geometry("560x300")

        screen_width = splash.winfo_screenwidth()
        screen_height = splash.winfo_screenheight()
        x_position = int((screen_width - 560) / 2)
        y_position = int((screen_height - 300) / 2)
        splash.geometry(f"560x300+{x_position}+{y_position}")

        splash_frame = ctk.CTkFrame(splash, corner_radius=18)
        splash_frame.pack(fill="both", expand=True, padx=16, pady=16)
        if self.logo_image_large:
            ctk.CTkLabel(splash_frame, image=self.logo_image_large, text="").pack(pady=(28, 10))
        ctk.CTkLabel(splash_frame, text="TorTraceAnalyzer", font=ctk.CTkFont(size=30, weight="bold")).pack()
        ctk.CTkLabel(splash_frame, text="Preparing the forensic workspace...", text_color="#9fb2c3").pack(pady=(8, 18))
        progress = ctk.CTkProgressBar(splash_frame, width=320)
        progress.pack()
        progress.set(0.72)

        def continue_startup():
            try:
                splash.destroy()
            except Exception:
                pass
            self.show_case_manager(initial_launch=True)

        self.startup_after_id = self.after(1300, continue_startup)

    def show_case_manager(self, initial_launch=False):
        if self.analysis_running:
            messagebox.showinfo("Analysis Running", "Finish the current analysis before changing the case.")
            return

        dialog = ctk.CTkToplevel(self)
        dialog.title("Case Workspace")
        dialog.geometry("980x640")
        dialog.minsize(900, 580)
        dialog.grab_set()
        dialog.transient(self)
        dialog.protocol("WM_DELETE_WINDOW", lambda: self._close_case_dialog(dialog, initial_launch))

        shell = ctk.CTkFrame(dialog, corner_radius=18)
        shell.pack(fill="both", expand=True, padx=18, pady=18)
        left = ctk.CTkFrame(shell, width=320, corner_radius=16)
        left.pack(side="left", fill="y", padx=(0, 14), pady=14)
        left.pack_propagate(False)
        if self.logo_image_large:
            ctk.CTkLabel(left, image=self.logo_image_large, text="").pack(pady=(32, 14))
        ctk.CTkLabel(left, text="Case Workspace", font=ctk.CTkFont(size=24, weight="bold")).pack(padx=18)
        ctk.CTkLabel(
            left,
            text="Create a new investigation or reopen a saved case.",
            wraplength=260,
            justify="left",
            text_color="#9fb2c3",
        ).pack(padx=20, pady=(14, 10))

        right = ctk.CTkFrame(shell, corner_radius=16)
        right.pack(side="left", fill="both", expand=True, pady=14)
        tabs = ctk.CTkTabview(right)
        tabs.pack(fill="both", expand=True, padx=14, pady=14)
        create_tab = tabs.add("Create New Case")
        open_tab = tabs.add("Open Previous")

        create_scroll = ctk.CTkScrollableFrame(create_tab)
        create_scroll.pack(fill="both", expand=True, padx=8, pady=8)
        form_entries = {}
        initial_values = dict(self.case_info)
        for key, label in CASE_FIELDS[:-1]:
            ctk.CTkLabel(create_scroll, text=label, anchor="w").pack(fill="x", padx=6, pady=(10, 4))
            entry = ctk.CTkEntry(create_scroll, placeholder_text=label)
            if initial_values.get(key):
                entry.insert(0, initial_values.get(key, ""))
            elif key == "case_id":
                entry.insert(0, self._default_case_info()["case_id"])
            entry.pack(fill="x", padx=6)
            form_entries[key] = entry
        ctk.CTkLabel(create_scroll, text="Description", anchor="w").pack(fill="x", padx=6, pady=(10, 4))
        description_box = ctk.CTkTextbox(create_scroll, height=120)
        description_box.pack(fill="both", expand=True, padx=6, pady=(0, 10))
        description_box.insert("1.0", initial_values.get("case_description", ""))
        create_actions = ctk.CTkFrame(create_tab, fg_color="transparent")
        create_actions.pack(fill="x", padx=12, pady=(0, 10))
        ctk.CTkButton(create_actions, text="Start New Case", command=lambda: self._submit_new_case(dialog, form_entries, description_box), fg_color="#1f8b4c", hover_color="#176d3c").pack(side="right")

        saved_case_names = get_case_names() or ["No Cases"]
        self.startup_case_var = tk.StringVar(value=saved_case_names[0])
        picker_frame = ctk.CTkFrame(open_tab, fg_color="transparent")
        picker_frame.pack(fill="x", padx=12, pady=(14, 8))
        previous_menu = ctk.CTkOptionMenu(picker_frame, values=saved_case_names, variable=self.startup_case_var, command=self._update_saved_case_summary, width=260)
        previous_menu.pack(side="left", padx=(0, 10))
        ctk.CTkButton(picker_frame, text="Open Selected Case", command=lambda: self._open_saved_case(dialog, self.startup_case_var.get()), state="disabled" if saved_case_names == ["No Cases"] else "normal").pack(side="left")
        self.saved_case_summary_box = ctk.CTkTextbox(open_tab, height=360)
        self.saved_case_summary_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._update_saved_case_summary(self.startup_case_var.get())

        self.case_dialog = dialog
        self.wait_window(dialog)
        if initial_launch and not self.startup_complete and self.winfo_exists():
            self.destroy()

    def _submit_new_case(self, dialog, form_entries, description_box):
        case_data = self._default_case_info()
        for key, _label in CASE_FIELDS[:-1]:
            case_data[key] = form_entries[key].get().strip()
        case_data["case_description"] = description_box.get("1.0", tk.END).strip()
        if not case_data["case_name"]:
            messagebox.showwarning("Case Name Required", "Please enter a case name before continuing.")
            return
        if not case_data["case_id"]:
            case_data["case_id"] = self._default_case_info()["case_id"]
        self._finish_case_setup(dialog, case_data)

    def _open_saved_case(self, dialog, case_name):
        case = get_case_by_name(case_name)
        if not case:
            messagebox.showwarning("Case Not Found", "Select a saved case to continue.")
            return
        self._finish_case_setup(dialog, case)

    def _finish_case_setup(self, dialog, case_data):
        self.case_info = dict(self._default_case_info())
        self.case_info.update(case_data or {})
        self.startup_complete = True
        self._refresh_case_menu(select_name=self.case_info.get("case_name"))
        self._update_case_summary()
        try:
            dialog.grab_release()
        except Exception:
            pass
        dialog.destroy()
        self.deiconify()
        self.lift()
        self.focus_force()
        if self._case_has_saved_results(case_data):
            self._restore_saved_case(case_data)

    def _close_case_dialog(self, dialog, initial_launch):
        try:
            dialog.grab_release()
        except Exception:
            pass
        dialog.destroy()
        if initial_launch:
            self.destroy()

    def _update_saved_case_summary(self, case_name):
        if not hasattr(self, "saved_case_summary_box"):
            return
        self.saved_case_summary_box.delete("1.0", tk.END)
        case = get_case_by_name(case_name)
        if not case:
            self.saved_case_summary_box.insert("1.0", "No saved cases are available yet.")
            return
        lines = [
            f"Case Name: {case.get('case_name', 'Unknown')}",
            f"Case ID: {case.get('case_id', '')}",
            f"Investigator: {case.get('investigator', '')}",
            f"Organization: {case.get('organization', '')}",
            f"Department: {case.get('department', '')}",
            f"Contact Email: {case.get('contact_email', '')}",
            f"Artifacts: {case.get('artifact_count', 0)}",
            f"FCI Score: {case.get('fci_score', 0)}",
            f"Determination: {case.get('determination', '')}",
            "",
            "Description:",
            case.get("case_description", "No description saved."),
        ]
        detections = case.get("all_detections", [])
        if detections:
            lines.extend(["", "Artifact Preview:"])
            for detection in detections[:8]:
                lines.append(f"- [{detection.get('layer', 'Unknown')}] {detection.get('file_name', 'Unknown')}")
            if len(detections) > 8:
                lines.append(f"... {len(detections) - 8} more artifacts saved in this case.")
        self.saved_case_summary_box.insert("1.0", "\n".join(lines))

    def _update_case_summary(self):
        case_name = self.case_info.get("case_name", "No Case")
        investigator = self.case_info.get("investigator") or "Unassigned Investigator"
        case_id = self.case_info.get("case_id") or "No ID"
        self.case_summary.set(f"Case: {case_name}\n{case_id} | {investigator}")

    def _case_has_saved_results(self, case):
        return bool(case and (case.get("all_detections") or case.get("layer_results") or case.get("timeline")))

    def _restore_saved_case(self, case):
        result = {
            "evidence_files": case.get("evidence_files", []),
            "layer_results": case.get("layer_results", {layer: [] for layer in self.layer_data}),
            "all_detections": case.get("all_detections", []),
            "correlation": {
                "summary": case.get("correlation_summary", ""),
                "correlations": case.get("correlation_items", []),
            },
            "fci_score": case.get("fci_score", 0),
            "determination": case.get("determination", ""),
            "timeline": case.get("timeline", {"events": [], "summary": ""}),
            "report_path": case.get("report_path", ""),
        }
        self.dashboard_messages = list(case.get("dashboard_messages", []))
        self.notes_box.delete("1.0", tk.END)
        self.notes_box.insert("1.0", case.get("notes", "Investigator notes and conclusions..."))
        self.apply_analysis_result(result, persist_case=False)
        self.status.set("LOADED SAVED CASE")
        self.current_file.set("Current file: Showing saved case history")

    def _refresh_case_menu(self, select_name=None):
        values = get_case_names() or ["No Cases"]
        if hasattr(self, "case_select"):
            self.case_select.configure(values=values)
            target = select_name if select_name in values else values[0]
            self.case_select.set(target)

    def _set_busy_state(self, running):
        state = "disabled" if running else "normal"
        for widget_name in [
            "files_button",
            "folder_button",
            "run_button",
            "manage_case_button",
            "search_button",
            "activity_matrix_button",
            "event_pie_button",
            "relation_button",
            "export_button",
            "case_select",
            "timeline_refresh_button",
            "smart_btn",
            "format_menu",
        ]:
            widget = getattr(self, widget_name, None)
            if widget is not None:
                try:
                    widget.configure(state=state)
                except Exception:
                    pass
        abort_state = "normal" if running else "disabled"
        try:
            self.abort_button.configure(state=abort_state)
        except Exception:
            pass

    def _clear_visual_canvas(self):
        if self.current_figure is not None:
            plt.close(self.current_figure)
            self.current_figure = None
        self.graph_canvas = None
        for widget in self.graph_canvas_frame.winfo_children():
            widget.destroy()

    def _show_visual_placeholder(self, message):
        self._clear_visual_canvas()
        try:
            self.side_workspace.set("VISUALS")
        except Exception:
            pass
        placeholder = ctk.CTkLabel(self.graph_canvas_frame, text=message, text_color="#8ea6b5", justify="center", wraplength=500)
        placeholder.pack(expand=True)

    def _display_figure(self, figure, title):
        if figure is None:
            self.graph_label.configure(text=title)
            self._show_visual_placeholder("No visual data available for this view.")
            return
        self._clear_visual_canvas()
        self.current_figure = figure
        self.graph_canvas = FigureCanvasTkAgg(figure, master=self.graph_canvas_frame)
        self.graph_canvas.draw()
        self.graph_canvas.get_tk_widget().pack(fill="both", expand=True)
        self.graph_label.configure(text=title)
        try:
            self.side_workspace.set("VISUALS")
        except Exception:
            pass

    def _update_selected_path_entry(self):
        if not self.selected_paths:
            self.path_entry.delete(0, tk.END)
            return
        display = self.selected_paths[0] if len(self.selected_paths) == 1 else f"{len(self.selected_paths)} evidence sources selected"
        self.path_entry.delete(0, tk.END)
        self.path_entry.insert(0, display)

    def on_close(self):
        if self.analysis_running:
            self.abort_analysis(prompt=False, closing=True)
        for attr_name in ["timer_after_id", "queue_after_id", "startup_after_id"]:
            self._cancel_after_callback(attr_name)
        self._cleanup_analysis_resources()
        try:
            self.destroy()
        except Exception:
            pass

    def _drain_output_queue(self):
        if self.output_queue is None:
            return
        while True:
            try:
                self.output_queue.get_nowait()
            except Exception:
                break

    def _cleanup_analysis_resources(self):
        if self.analysis_process is not None:
            try:
                if self.analysis_process.is_alive():
                    self.analysis_process.join(timeout=0.2)
            except Exception:
                pass
            try:
                self.analysis_process.close()
            except Exception:
                pass
            self.analysis_process = None

        if self.output_queue is not None and hasattr(self.output_queue, "close"):
            try:
                self.output_queue.close()
            except Exception:
                pass
            try:
                self.output_queue.join_thread()
            except Exception:
                pass
            self.output_queue = queue.Queue()

    def _finish_aborted_analysis(self):
        self._cancel_after_callback("queue_after_id")
        self._cancel_after_callback("timer_after_id")
        self.analysis_running = False
        self.start_time = None
        self._set_busy_state(False)
        self._drain_output_queue()
        self._cleanup_analysis_resources()
        self.status.set("ABORTED")
        self.timer.set("Aborted")
        self.current_file.set("Current file: Analysis aborted")
        self.write("dashboard", "Analysis aborted by user.", "high")

    def abort_analysis(self, prompt=True, closing=False):
        if not self.analysis_running:
            return

        if prompt and not self.test_mode:
            confirmed = messagebox.askyesno(
                "Abort Analysis",
                "Stop the current analysis? Partial progress will not be saved.",
            )
            if not confirmed:
                return

        self.analysis_aborted = True
        self.status.set("Aborting analysis...")
        self.current_file.set("Current file: Stopping analysis")

        if self.analysis_process is not None:
            try:
                if self.analysis_process.is_alive():
                    self.analysis_process.terminate()
            except Exception:
                pass
            try:
                if self.analysis_process.is_alive():
                    self.analysis_process.kill()
            except Exception:
                pass
            try:
                self.analysis_process.join(timeout=0.5)
            except Exception:
                pass

        self._finish_aborted_analysis()

        if not closing and not self.test_mode:
            messagebox.showinfo("Analysis Aborted", "The current analysis was stopped.")

    def add_files(self):
        files = filedialog.askopenfilenames()
        if files:
            self.selected_paths = list(files)
            self._update_selected_path_entry()

    def add_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.selected_paths = [folder]
            self._update_selected_path_entry()

    def load_selected_case(self, case_name):
        case = get_case_by_name(case_name)
        if not case:
            return
        self.case_info = dict(self._default_case_info())
        self.case_info.update(case)
        self._update_case_summary()
        if self._case_has_saved_results(case):
            self._restore_saved_case(case)
            return
        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, f"Loaded Case: {case_name}\n", "artifact")
        self.output.insert(tk.END, f"Case ID: {case.get('case_id', '')}\n", "normal")
        self.output.insert(tk.END, f"Artifacts: {case.get('artifact_count', 0)}\n", "normal")
        self.output.insert(tk.END, f"FCI: {case.get('fci_score', 0)}%\n", "normal")
        self.output.insert(tk.END, f"Determination: {case.get('determination', '')}\n", "high")
        self.tabview.set("DASHBOARD")
    def start_analysis(self):
        if self.analysis_running:
            messagebox.showinfo("Analysis Running", "Analysis is already in progress.")
            return
        if not self.selected_paths:
            messagebox.showwarning("No Evidence Selected", "Choose evidence files or a folder before running analysis.")
            return

        self.analysis_aborted = False
        self.analysis_running = True
        self._set_busy_state(True)
        self.start_time = time.time()
        self.progress.set(0)
        self.status.set("Starting analysis...")
        self.timer.set("Elapsed: 0s")
        self.current_file.set("Current file: Preparing evidence list...")
        self._show_visual_placeholder("Preparing visuals...")

        self.timeline_data = {}
        self.all_findings = []
        self.all_detections = []
        self.fci_score = 0.0
        self.determination = ""
        self.correlation_summary = ""
        self.correlation_items = []
        self.report_path = ""
        self.dashboard_messages = []
        self._cleanup_analysis_resources()
        self.output_queue = self.mp_context.Queue()
        self.latest_evidence_files = []

        for key in self.layer_data:
            self.layer_data[key] = []
        for tab in self.tabs.values():
            tab.delete("1.0", tk.END)
        self._clear_layer_tables()
        self._clear_timeline_table()

        self.tabview.set("DASHBOARD")
        self.write("dashboard", "Starting analysis...", "medium")
        self.analysis_process = self.mp_context.Process(
            target=run_analysis_process,
            args=(list(self.selected_paths), dict(self.case_info), self.output_queue),
            daemon=True,
        )
        self.analysis_process.start()
        self.update_timer()
        self.process_output_queue()

    def update_timer(self):
        if not self.analysis_running or not self.start_time:
            self.timer_after_id = None
            return
        elapsed = int(time.time() - self.start_time)
        self.timer.set(f"Elapsed: {elapsed}s")
        if elapsed >= 15:
            self.status.set("Still working... large files can take longer")
        self.timer_after_id = self.after(1000, self.update_timer)

    def process_output_queue(self):
        self.queue_after_id = None
        processed = 0
        max_events_per_cycle = 20
        while processed < max_events_per_cycle:
            try:
                event = self.output_queue.get_nowait()
            except queue.Empty:
                break
            self.handle_event(event)
            processed += 1
        if self.analysis_running and self.analysis_process is not None and not self.analysis_process.is_alive():
            if self.output_queue.empty():
                if self.analysis_aborted:
                    self._finish_aborted_analysis()
                    return
                self.handle_event(
                    {
                        "type": "worker_error",
                        "message": "Analysis process stopped unexpectedly.",
                        "traceback": "",
                    }
                )
                return
        if self.analysis_running or processed > 0:
            self.queue_after_id = self.after(40 if processed >= max_events_per_cycle else 100, self.process_output_queue)

    def handle_event(self, event):
        event_type = event.get("type")
        if self.analysis_aborted:
            return
        if event_type == "progress":
            value = max(0, min(100, int(event.get("value", 0))))
            self.progress.set(value / 100)
            self.status.set(event.get("message", f"{value}%"))
            return
        if event_type == "status":
            message = event.get("message", "")
            if message:
                if message.startswith("Analyzing "):
                    self.current_file.set(f"Current file: {message.replace('Analyzing ', '', 1)}")
                else:
                    self.dashboard_messages.append(message)
                    self.write("dashboard", message, self._tag_for_level(event.get("level", "normal")))
            return
        if event_type == "error":
            message = event.get("message", "Unknown analysis error")
            self.dashboard_messages.append(message)
            self.write("dashboard", message, "critical")
            return
        if event_type == "complete":
            if self.analysis_process is not None:
                try:
                    self.analysis_process.join(timeout=0.2)
                except Exception:
                    pass
            self.apply_analysis_result(event.get("result", {}))
            return
        if event_type == "worker_error":
            self._cancel_after_callback("timer_after_id")
            self._cancel_after_callback("queue_after_id")
            self.analysis_running = False
            self.start_time = None
            self._set_busy_state(False)
            if self.analysis_process is not None:
                try:
                    if self.analysis_process.is_alive():
                        self.analysis_process.terminate()
                except Exception:
                    pass
                try:
                    self.analysis_process.join(timeout=0.2)
                except Exception:
                    pass
            self._cleanup_analysis_resources()
            self.status.set("FAILED")
            self.current_file.set("Current file: Analysis stopped")
            self.write("dashboard", event.get("message", "Worker error"), "critical")
            tb = event.get("traceback")
            if tb:
                self.write("dashboard", tb, "muted")
            messagebox.showerror("Analysis Error", event.get("message", "Worker error"))

    def apply_analysis_result(self, result, persist_case=True):
        self._cancel_after_callback("timer_after_id")
        self._cancel_after_callback("queue_after_id")
        self.analysis_running = False
        self.start_time = None
        self._set_busy_state(False)
        self._cleanup_analysis_resources()
        if not result:
            self.status.set("DONE")
            self.progress.set(1)
            self.timer.set("Completed")
            self.current_file.set("Current file: Completed")
            return

        self.all_detections = list(result.get("all_detections", []))
        self.all_findings = [d.get("file_name", "UNKNOWN") for d in self.all_detections]
        self.fci_score = float(result.get("fci_score", 0))
        self.determination = result.get("determination", "")
        self.correlation_summary = result.get("correlation", {}).get("summary", "")
        self.correlation_items = result.get("correlation", {}).get("correlations", [])
        self.timeline_data = result.get("timeline", {})
        self.report_path = result.get("report_path", "")
        layer_results = result.get("layer_results", {})
        self.latest_layer_results = layer_results
        self.latest_evidence_files = result.get("evidence_files", [])

        for key in self.layer_data:
            self.layer_data[key] = []

        self.render_dashboard(result)
        self.render_layers(layer_results)
        self.show_timeline(activate_tab=False)

        if persist_case:
            case_record = dict(self.case_info)
            case_record.update({
                "fci_score": self.fci_score,
                "determination": self.determination,
                "correlation_summary": self.correlation_summary,
                "correlation_items": self.correlation_items,
                "artifact_count": len(self.all_detections),
                "date_completed": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "evidence_files": self.latest_evidence_files,
                "layer_results": layer_results,
                "all_detections": self.all_detections,
                "timeline": self.timeline_data,
                "report_path": self.report_path,
                "dashboard_messages": self.dashboard_messages[-100:],
                "notes": self.notes_box.get("1.0", tk.END).strip(),
            })
            save_case(case_record)
            self._refresh_case_menu(select_name=self.case_info.get("case_name"))

        self.progress.set(1)
        self.status.set("DONE")
        self.timer.set("Completed")
        self.current_file.set("Current file: Completed")
        self.tabview.set("DASHBOARD")

    def render_dashboard(self, result):
        tab = self.tabs["dashboard"]
        tab.delete("1.0", tk.END)
        total_artifacts = len(self.all_detections)
        active_layers = len([name for name, items in result.get("layer_results", {}).items() if items])
        evidence_count = len(result.get("evidence_files", []))

        if self.fci_score >= 70:
            risk = "HIGH"
        elif self.fci_score >= 40:
            risk = "MEDIUM"
        elif total_artifacts > 0:
            risk = "LOW"
        else:
            risk = "NONE"

        tab.insert(tk.END, "TOR TRACE ANALYZER\n", "critical")
        tab.insert(tk.END, "MULTI-LAYER FORENSIC SUMMARY\n\n", "high")
        tab.insert(tk.END, "========== CASE ==========\n", "high")
        for key, label in CASE_FIELDS:
            value = self.case_info.get(key, "")
            if value:
                tab.insert(tk.END, f"{label:<14}: {value}\n", "normal")
        tab.insert(tk.END, "\n", "normal")
        tab.insert(tk.END, "========== EXECUTIVE SUMMARY ==========\n", "high")
        tab.insert(tk.END, f"Evidence Files : {evidence_count}\n", "normal")
        tab.insert(tk.END, f"Active Layers  : {active_layers}\n", "medium")
        tab.insert(tk.END, f"Detections     : {total_artifacts}\n", "artifact")
        tab.insert(tk.END, f"FCI Score      : {self.fci_score:.2f}%\n", "critical")
        tab.insert(tk.END, f"Risk Level     : {risk}\n", "critical")
        tab.insert(tk.END, f"Determination  : {self.determination or 'No determination generated'}\n", "high")
        if self.report_path:
            tab.insert(tk.END, f"Auto Report    : {self.report_path}\n", "muted")
        tab.insert(tk.END, "\n", "normal")
        tab.insert(tk.END, "Per-Layer Detections\n", "high")
        for layer_name in ["memory", "system", "network", "application", "transport"]:
            count = len(result.get("layer_results", {}).get(layer_name, []))
            tab.insert(tk.END, f"- {layer_name.title():<11}: {count}\n", "normal" if count == 0 else "artifact")
        tab.insert(tk.END, "\n", "normal")
        tab.insert(tk.END, "========== CORRELATION FINDINGS ==========\n", "high")
        if self.correlation_items:
            tab.insert(tk.END, "Why the tool correlated this case:\n", "muted")
            for item in self.correlation_items:
                severity, title, explanation = self._parse_correlation_item(item)
                tab.insert(tk.END, f"[{severity}] {title}\n", self._tag_for_correlation(item))
                tab.insert(tk.END, f"    {explanation}\n", "normal")
        else:
            tab.insert(tk.END, "No cross-layer correlation found.\n", "normal")
        tab.insert(tk.END, "\n", "normal")
        tab.insert(tk.END, "========== DETECTED ARTIFACTS ==========\n", "high")
        if not self.all_detections:
            tab.insert(tk.END, "No detections were produced from the selected inputs.\n", "normal")
        else:
            for detection in self.all_detections:
                artifact_line = f"[{detection.get('layer', 'UNKNOWN')}] {detection.get('file_name', 'UNKNOWN')} | {detection.get('message', 'No message')}"
                tab.insert(tk.END, artifact_line + "\n", "artifact")
        tab.insert(tk.END, "\n", "normal")
        if self.dashboard_messages:
            tab.insert(tk.END, "========== ENGINE MESSAGES ==========\n", "high")
            for message in self.dashboard_messages:
                self.write("dashboard", message, "muted")
        tab.see(tk.END)

    def render_layers(self, layer_results):
        for layer in ["memory", "system", "network", "application", "transport"]:
            table = self.layer_tables.get(layer)
            if table is None:
                continue

            for item_id in table.get_children():
                table.delete(item_id)

            entries = []
            detections = list(layer_results.get(layer, []))
            for detection in detections:
                values = self._layer_row_values(detection)
                item_id = table.insert("", "end", values=values, tags=(self._layer_row_tag(detection),))
                entries.append(
                    {
                        "item_id": item_id,
                        "search_text": self._layer_search_text(detection),
                        "detection": detection,
                    }
                )

            self.layer_data[layer] = entries
            count = len(entries)
            if layer in self.layer_summary_vars:
                if count == 0:
                    self.layer_summary_vars[layer].set(f"No {layer} detections in this case.")
                else:
                    self.layer_summary_vars[layer].set(f"{count} detection{'s' if count != 1 else ''} loaded.")

            if entries:
                first_item = entries[0]["item_id"]
                table.selection_set(first_item)
                table.focus(first_item)
                table.see(first_item)
                self._on_layer_select(layer)
            else:
                self._set_layer_detail(layer, f"No {layer} detections are available for the current case.")

    def format_detection_block(self, detection):
        timestamps = detection.get("disk_timestamps", {})
        layer = str(detection.get("layer", "")).title()
        lines = [
            (f"STATUS   : {detection.get('status', 'Detected')}", "artifact"),
            (f"ARTIFACT : {detection.get('file_name', 'UNKNOWN')}", "artifact"),
            (f"PATH     : {detection.get('file_path', 'N/A')}", "normal"),
            (f"EVIDENCE : {detection.get('evidence_match', 'N/A')}", "medium"),
            (f"NOTE     : {detection.get('message', 'No message')}", "normal"),
        ]
        if layer in {"System", "Application"}:
            lines.extend(
                [
                    (f"MODIFIED : {timestamps.get('modified', 'N/A')}", "normal"),
                    (f"CREATED  : {timestamps.get('created', 'N/A')}", "normal"),
                    (f"ACCESSED : {timestamps.get('accessed', 'N/A')}", "normal"),
                ]
            )
        lines.append(("------------------------------", "muted"))
        return lines

    def write(self, tab, text, explicit_tag=None):
        widget = self.tabs.get(tab, self.tabs["dashboard"])
        widget.insert(tk.END, text.replace("------------------------------", "-" * 30) + "\n", explicit_tag or "normal")
        widget.see(tk.END)

    def _tag_for_level(self, level):
        return {"error": "critical", "warning": "high", "info": "medium", "normal": "normal"}.get(level, "normal")

    def _parse_correlation_item(self, item):
        parts = [part.strip() for part in str(item).split("|", 2)]
        if len(parts) == 3:
            return parts[0], parts[1], parts[2]
        text = str(item).strip()
        severity = text.split(":", 1)[0].strip() if ":" in text else "INFO"
        explanation = text.split(":", 1)[1].strip() if ":" in text else text
        return severity, "Correlation finding", explanation

    def _tag_for_correlation(self, item):
        upper = str(item).upper()
        if upper.startswith("CRITICAL"):
            return "critical"
        if upper.startswith("HIGH"):
            return "high"
        if upper.startswith("MEDIUM"):
            return "medium"
        return "normal"
    def on_artifact_click(self, event):
        widget = event.widget
        index = widget.index(f"@{event.x},{event.y}")
        line = widget.get(f"{index} linestart", f"{index} lineend").strip()
        if not line:
            return

        if line.startswith("[") and "]" in line:
            layer_name = line[1: line.index("]")].strip().lower()
            artifact_hint = line.split("]", 1)[1].split("|", 1)[0].strip()
            if artifact_hint:
                self.jump_to_layer(layer_name, artifact_hint)
                return

        for layer, entries in self.layer_data.items():
            for entry in entries:
                if line.lower() in entry.get("search_text", "").lower():
                    self.jump_to_layer(layer, line)
                    return

    def jump_to_layer(self, layer, keyword):
        if layer not in self.layer_tables:
            return
        self.tabview.set(layer.upper())
        entry = self._find_layer_detection(layer, keyword)
        if not entry:
            return
        table = self.layer_tables[layer]
        item_id = entry["item_id"]
        table.selection_set(item_id)
        table.focus(item_id)
        table.see(item_id)
        self._on_layer_select(layer)

    def search_text(self):
        keyword = self.search_var.get().strip()
        for tab in self.tabs.values():
            tab.tag_remove("highlight", "1.0", tk.END)
            if not keyword:
                continue
            idx = "1.0"
            while True:
                idx = tab.search(keyword, idx, nocase=1, stopindex=tk.END)
                if not idx:
                    break
                end = f"{idx}+{len(keyword)}c"
                tab.tag_add("highlight", idx, end)
                tab.tag_config("highlight", background="#feca57", foreground="#111827")
                idx = end

        if keyword:
            for layer in ["memory", "system", "network", "application", "transport"]:
                entry = self._find_layer_detection(layer, keyword)
                if entry:
                    self.tabview.set(layer.upper())
                    table = self.layer_tables[layer]
                    table.selection_set(entry["item_id"])
                    table.focus(entry["item_id"])
                    table.see(entry["item_id"])
                    self._on_layer_select(layer)
                    break

        if hasattr(self, "timeline_table"):
            for item_id in self.timeline_table.selection():
                self.timeline_table.selection_remove(item_id)
            if keyword:
                for item_id in self.timeline_table.get_children():
                    values = self.timeline_table.item(item_id, "values")
                    if keyword.lower() in " ".join(str(value) for value in values).lower():
                        self.timeline_table.selection_set(item_id)
                        self.timeline_table.focus(item_id)
                        self.timeline_table.see(item_id)
                        self._on_timeline_select()
                        break

    def _parse_timeline_time(self, value):
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(value, fmt)
            except (TypeError, ValueError):
                continue
        return None

    def _get_filtered_timeline_events(self):
        events = list(self.timeline_data.get("events", []))
        filter_type = self.filter_var.get()
        start_raw = self.start_date.get().strip()
        end_raw = self.end_date.get().strip()
        try:
            start_dt = datetime.strptime(start_raw, "%Y-%m-%d") if start_raw else None
            end_dt = datetime.strptime(end_raw, "%Y-%m-%d") if end_raw else None
        except ValueError:
            start_dt = None
            end_dt = None

        filtered = []
        for event in events:
            event_type = event.get("type", "")
            if filter_type != "ALL" and event_type != filter_type:
                continue
            parsed_time = self._parse_timeline_time(event.get("time"))
            if not parsed_time:
                continue
            if start_dt and parsed_time < start_dt:
                continue
            if end_dt and parsed_time > end_dt:
                continue
            filtered.append(event)
        filtered.sort(key=lambda item: self._parse_timeline_time(item.get("time")) or datetime.max)
        if self.smart_mode and len(filtered) > 12:
            filtered = filtered[-12:]
        return filtered

    def show_activity_matrix(self):
        filtered_events = self._get_filtered_timeline_events()
        if not filtered_events:
            messagebox.showwarning("No Timeline Data", "No timeline events are available for the current case or filters.")
            return
        figure = build_activity_matrix_figure({"events": filtered_events})
        self._display_figure(figure, "Activity Matrix")

    def show_graph(self):
        self.show_activity_matrix()

    def show_pie_chart(self):
        if not self.all_detections:
            messagebox.showwarning("No Detection Data", "Run analysis first to generate detections.")
            return
        figure = build_detection_pie_figure(self.all_detections)
        self._display_figure(figure, "Evidence Pie")

    def show_timeline(self, activate_tab=True):
        events = self._get_filtered_timeline_events()
        if not events:
            self._clear_timeline_table("No timeline events are available for the current case.")
            return
        if activate_tab:
            self.tabview.set("TIMELINE")

        self._clear_timeline_table()

        event_counts = {}
        for event in events:
            event_type = event.get("type", "UNKNOWN")
            event_counts[event_type] = event_counts.get(event_type, 0) + 1

            values = (
                event.get("time", "N/A"),
                event_type,
                event.get("layer", "UNKNOWN"),
                event.get("artifact") or event.get("file_name") or "UNKNOWN",
            )
            self.timeline_table.insert("", "end", values=values, tags=(self._timeline_row_tag(event_type),))

        summary_parts = [f"{count} {event_type.lower()}" for event_type, count in event_counts.items()]
        summary_text = f"{len(events)} timeline rows loaded"
        if summary_parts:
            summary_text += " | " + ", ".join(summary_parts)
        self.timeline_summary.set(summary_text)

        children = self.timeline_table.get_children()
        if children:
            self.timeline_table.selection_set(children[0])
            self.timeline_table.focus(children[0])
            self.timeline_table.see(children[0])
            self._on_timeline_select()
        else:
            self._set_timeline_detail("Select a timeline row to inspect its artifact details.")

    def build_detections(self):
        return list(self.all_detections)

    def toggle_smart(self):
        self.smart_mode = not self.smart_mode
        self.smart_btn.configure(text=f"Recent Focus: {'On' if self.smart_mode else 'Off'}")
        self.show_timeline()

    def show_relation(self):
        if not self.all_detections:
            messagebox.showwarning("No Detections", "Run analysis first to generate artifact relationships.")
            return
        figure = build_relationship_figure(self.all_detections)
        self._display_figure(figure, "Relations Map")

    def export(self):
        from report_generator import export_custom_report

        if not self.all_detections:
            messagebox.showwarning("No Results", "Run analysis first before exporting a report.")
            return

        file_types = [("PDF Files", "*.pdf"), ("Text Files", "*.txt"), ("Excel Files", "*.xlsx"), ("CSV Files", "*.csv"), ("JSON Files", "*.json")]
        path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=file_types)
        if not path:
            return

        ext = os.path.splitext(path)[1].lower()
        format_type = {".pdf": "PDF", ".txt": "TXT", ".xlsx": "EXCEL", ".csv": "CSV", ".json": "JSON"}.get(ext, "PDF")
        notes = self.notes_box.get("1.0", tk.END).strip()
        case_info = dict(self.case_info)
        case_info["date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        visual_paths = []
        activity_path = save_activity_matrix_figure(self.timeline_data, get_temp_graph_path("activity_matrix.png"))
        if activity_path:
            visual_paths.append({"title": "Activity Matrix", "path": activity_path})
            case_info["graph_path"] = activity_path
        pie_path = save_detection_pie_figure(self.all_detections, get_temp_graph_path("evidence_pie.png"))
        if pie_path:
            visual_paths.append({"title": "Evidence Pie", "path": pie_path})
        relation_path = save_relationship_figure(self.all_detections, get_temp_graph_path("relation_map.png"))
        if relation_path:
            visual_paths.append({"title": "Relations Map", "path": relation_path})

        export_custom_report(self.all_detections, self.fci_score, self.determination, self.correlation_summary, self.timeline_data, format_type, path, case_info=case_info, notes=notes, visual_paths=visual_paths, correlation_items=self.correlation_items)
        case_snapshot = dict(self.case_info)
        case_snapshot.update({
            "fci_score": self.fci_score,
            "determination": self.determination,
            "correlation_summary": self.correlation_summary,
            "correlation_items": self.correlation_items,
            "artifact_count": len(self.all_detections),
            "evidence_files": self.latest_evidence_files,
            "layer_results": self.latest_layer_results,
            "all_detections": self.all_detections,
            "timeline": self.timeline_data,
            "report_path": path,
            "dashboard_messages": self.dashboard_messages[-100:],
            "notes": notes,
        })
        save_case(case_snapshot)
        messagebox.showinfo("Report Saved", f"Report saved successfully:\n{path}")


if __name__ == "__main__":
    mp.freeze_support()
    app = TorTraceGUI()
    app.mainloop()


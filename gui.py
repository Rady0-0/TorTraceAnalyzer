import os
import queue
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox

import customtkinter as ctk

from app_paths import get_temp_graph_path, resource_path
from case_manager import get_case_names, save_case
from relation_graph import plot_relationship_embedded
from timeline_graph import plot_timeline, plot_timeline_embedded

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class TorTraceGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.title("TorTrace Analyzer")
        self.geometry("1400x900")
        self._set_window_icon()

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
        self.view_help = tk.StringVar(
            value="Run analysis first. Then use Timeline Graph, Event Pie, or Relations to explore the results."
        )
        self.date_help = tk.StringVar(
            value="Start and End dates only filter the TIMELINE tab after analysis. Format: YYYY-MM-DD."
        )
        self.current_file = tk.StringVar(value="Current file: Waiting to start")

        self.layer_data = {
            "memory": [],
            "system": [],
            "network": [],
            "application": [],
            "transport": [],
        }

        self.build_ui()
        self.case_info = self.get_case_details()

    def _set_window_icon(self):
        icon_path = resource_path(os.path.join("assets", "tortrace_icon.ico"))
        if os.path.exists(icon_path):
            try:
                self.iconbitmap(icon_path)
            except Exception:
                pass

    def build_ui(self):
        ctk.CTkLabel(
            self,
            text="TOR TRACE ANALYZER",
            font=ctk.CTkFont(size=32, weight="bold"),
        ).pack(pady=10)

        self.control_tabs = ctk.CTkTabview(self)
        self.control_tabs.pack(fill="x", padx=20, pady=(0, 10))

        case_tab = self.control_tabs.add("CASE & SEARCH")
        filter_tab = self.control_tabs.add("TIMELINE FILTERS")
        visual_tab = self.control_tabs.add("VISUALS & EXPORT")

        self.case_select = ctk.CTkOptionMenu(
            case_tab,
            values=get_case_names() or ["No Cases"],
            command=self.load_selected_case,
        )
        self.case_select.pack(side="left", padx=8, pady=10)

        self.search_var = tk.StringVar()
        self.filter_var = tk.StringVar(value="ALL")

        ctk.CTkEntry(case_tab, textvariable=self.search_var, width=280, placeholder_text="Search detected text in tabs").pack(side="left", padx=8, pady=10)
        ctk.CTkButton(case_tab, text="Search", command=self.search_text).pack(side="left", padx=8, pady=10)
        ctk.CTkLabel(
            case_tab,
            text="Choose a saved case or search inside the current analysis output.",
            text_color="#a5b1c2",
        ).pack(side="left", padx=12, pady=10)

        self.start_date = ctk.CTkEntry(filter_tab, placeholder_text="From date YYYY-MM-DD")
        self.start_date.pack(side="left", padx=8, pady=10)
        self.end_date = ctk.CTkEntry(filter_tab, placeholder_text="To date YYYY-MM-DD")
        self.end_date.pack(side="left", padx=8, pady=10)

        self.filter_menu = ctk.CTkOptionMenu(
            filter_tab,
            values=["ALL", "MODIFIED", "CREATED", "ACCESSED", "ANOMALY"],
            variable=self.filter_var,
            command=lambda _value: self.show_timeline(),
        )
        self.filter_menu.pack(side="left", padx=8, pady=10)
        self.smart_btn = ctk.CTkButton(filter_tab, text="Smart Mode", command=self.toggle_smart)
        self.smart_btn.pack(side="left", padx=8, pady=10)
        ctk.CTkLabel(
            filter_tab,
            text="These controls only change what you see in the TIMELINE tab after analysis.",
            text_color="#a5b1c2",
        ).pack(side="left", padx=12, pady=10)

        ctk.CTkButton(visual_tab, text="Explain Views", command=self.show_view_guide).pack(side="left", padx=8, pady=10)
        ctk.CTkButton(visual_tab, text="Timeline Graph", command=self.show_graph).pack(side="left", padx=8, pady=10)
        ctk.CTkButton(visual_tab, text="Event Pie", command=self.show_pie_chart).pack(side="left", padx=8, pady=10)
        self.rel_btn = ctk.CTkButton(visual_tab, text="Relations", command=self.show_relation)
        self.rel_btn.pack(side="left", padx=8, pady=10)

        self.format_menu = ctk.CTkComboBox(visual_tab, values=["TXT", "CSV", "EXCEL", "JSON", "PDF"])
        self.format_menu.set("PDF")
        self.format_menu.pack(side="left", padx=8, pady=10)

        ctk.CTkButton(visual_tab, text="EXPORT", command=self.export).pack(side="left", padx=8, pady=10)

        frame = ctk.CTkFrame(self)
        frame.pack(fill="x", padx=20, pady=10)

        self.path_entry = ctk.CTkEntry(frame)
        self.path_entry.pack(side="left", fill="x", expand=True, padx=5)

        ctk.CTkButton(frame, text="FILES", command=self.add_files).pack(side="left")
        ctk.CTkButton(frame, text="FOLDER", command=self.add_folder).pack(side="left")
        ctk.CTkButton(frame, text="RUN ANALYSIS", command=self.start_analysis).pack(side="left")

        self.progress = ctk.CTkProgressBar(self)
        self.progress.pack(fill="x", padx=20)
        self.progress.set(0)

        self.status = tk.StringVar(value="READY")
        self.timer = tk.StringVar(value="Elapsed: 0s")

        ctk.CTkLabel(self, textvariable=self.status).pack()
        ctk.CTkLabel(self, textvariable=self.timer).pack()
        ctk.CTkLabel(self, textvariable=self.current_file, text_color="#1dd1a1").pack()
        ctk.CTkLabel(self, textvariable=self.date_help, text_color="#a5b1c2").pack(pady=(0, 6))

        self.tabs = {}
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=10)

        self.graph_frame = ctk.CTkFrame(self, height=250)
        self.graph_frame.pack(fill="x", padx=20, pady=(0, 10))

        self.graph_label = ctk.CTkLabel(
            self.graph_frame,
            text="Visualization Panel",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        self.graph_label.pack(anchor="w", padx=10, pady=5)

        self.graph_help_label = ctk.CTkLabel(
            self.graph_frame,
            textvariable=self.view_help,
            justify="left",
            wraplength=1200,
            text_color="#c8d6e5",
        )
        self.graph_help_label.pack(anchor="w", padx=10, pady=(0, 8))

        self.notes_box = ctk.CTkTextbox(self.graph_frame, height=80)
        self.notes_box.pack(fill="x", padx=10, pady=(0, 10))
        self.notes_box.insert("1.0", "Investigator notes / conclusions...")

        self.graph_canvas_frame = ctk.CTkFrame(self.graph_frame)
        self.graph_canvas_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.graph_canvas = None

        for name in ["dashboard", "memory", "system", "network", "application", "transport", "timeline"]:
            tab = self.tabview.add(name.upper())
            text_widget = tk.Text(
                tab,
                bg="black",
                fg="white",
                insertbackground="white",
                font=("Consolas", 12),
                wrap="word",
            )
            text_widget.pack(fill="both", expand=True)
            text_widget.bind("<Button-1>", self.on_artifact_click)
            self.tabs[name] = text_widget

        for tab in self.tabs.values():
            tab.tag_config("critical", foreground="#ff4c4c", font=("Consolas", 11, "bold"))
            tab.tag_config("high", foreground="#ff9f43")
            tab.tag_config("medium", foreground="#00d2d3")
            tab.tag_config("artifact", foreground="#1dd1a1")
            tab.tag_config("normal", foreground="#c8d6e5")

        self.output = self.tabs["dashboard"]

    def on_close(self):
        self.analysis_running = False
        try:
            self.destroy()
        except Exception:
            pass

    def get_case_details(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Case Setup")
        dialog.geometry("400x300")

        ctk.CTkLabel(
            dialog,
            text="Enter Case Details",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(pady=10)

        case_name = ctk.CTkEntry(dialog, placeholder_text="Case Name")
        case_name.pack(pady=5)

        case_id = ctk.CTkEntry(dialog, placeholder_text="Case ID")
        case_id.pack(pady=5)

        investigator = ctk.CTkEntry(dialog, placeholder_text="Investigator Name")
        investigator.pack(pady=5)

        result = {}

        def submit():
            result["case_name"] = case_name.get()
            result["case_id"] = case_id.get()
            result["investigator"] = investigator.get()
            dialog.destroy()

        ctk.CTkButton(dialog, text="Start Analysis", command=submit).pack(pady=15)
        self.wait_window(dialog)
        return result

    def add_files(self):
        files = filedialog.askopenfilenames()
        if files:
            self.selected_paths = list(files)
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, str(files))

    def add_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            if folder not in self.selected_paths:
                self.selected_paths.append(folder)
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, folder)

    def load_selected_case(self, case_name):
        from case_manager import load_cases

        for case in load_cases():
            stored_name = case.get("case_name") or case.get("case_number")
            if stored_name == case_name:
                self.output.delete("1.0", tk.END)
                self.output.insert(tk.END, f"Loaded Case: {case_name}\n", "artifact")
                self.output.insert(
                    tk.END,
                    f"Artifacts: {case.get('artifact_count', case.get('artifacts', 0))}\n",
                    "normal",
                )
                self.output.insert(
                    tk.END,
                    f"FCI: {case.get('fci_score', case.get('fci', 0))}%\n",
                    "normal",
                )
                break

    def start_analysis(self):
        if self.analysis_running:
            messagebox.showinfo("Analysis Running", "Analysis is already in progress.")
            return

        if not self.selected_paths:
            messagebox.showwarning("Error", "Select input")
            return

        self.analysis_running = True
        self.start_time = time.time()
        self.progress.set(0)
        self.status.set("Starting analysis...")
        self.timer.set("Elapsed: 0s")
        self.current_file.set("Current file: Preparing evidence list...")
        self.view_help.set("Analysis is running. Please wait for detections before opening charts.")

        self.timeline_data = {}
        self.all_findings = []
        self.all_detections = []
        self.fci_score = 0.0
        self.determination = ""
        self.correlation_summary = ""
        self.report_path = ""
        self.dashboard_messages = []
        self.output_queue = queue.Queue()

        for key in self.layer_data:
            self.layer_data[key] = []

        for tab in self.tabs.values():
            tab.delete("1.0", tk.END)

        self.write("dashboard", "Starting analysis...", "medium")

        worker = threading.Thread(target=self.run_worker, daemon=True)
        worker.start()

        self.update_timer()
        self.process_output_queue()

    def update_timer(self):
        if not self.analysis_running or not self.start_time:
            return

        elapsed = int(time.time() - self.start_time)
        self.timer.set(f"Elapsed: {elapsed}s")
        if elapsed >= 15 and self.analysis_running:
            current_text = self.current_file.get()
            if current_text and "Current file:" in current_text:
                self.status.set("Still working... large files can take longer")
        self.after(1000, self.update_timer)

    def run_worker(self):
        try:
            from main import run_analysis

            def event_callback(event):
                self.output_queue.put(event)

            result = run_analysis(self.selected_paths, event_callback=event_callback)
            self.output_queue.put({"type": "complete", "result": result})
        except Exception as exc:
            self.output_queue.put({"type": "worker_error", "message": str(exc)})

    def process_output_queue(self):
        while True:
            try:
                event = self.output_queue.get_nowait()
            except queue.Empty:
                break

            self.handle_event(event)

        if self.analysis_running:
            self.after(100, self.process_output_queue)

    def handle_event(self, event):
        event_type = event.get("type")

        if event_type == "progress":
            value = max(0, min(100, int(event.get("value", 0))))
            self.progress.set(value / 100)
            self.status.set(event.get("message", f"{value}%"))
            return

        if event_type == "status":
            message = event.get("message", "")
            if message:
                self.dashboard_messages.append(message)
                self.write("dashboard", message, self._tag_for_level(event.get("level", "normal")))
                if message.startswith("Analyzing "):
                    self.current_file.set(f"Current file: {message.replace('Analyzing ', '', 1)}")
            return

        if event_type == "error":
            message = event.get("message", "Unknown analysis error")
            self.dashboard_messages.append(message)
            self.write("dashboard", message, "critical")
            return

        if event_type == "complete":
            self.apply_analysis_result(event.get("result", {}))
            return

        if event_type == "worker_error":
            self.analysis_running = False
            self.status.set("FAILED")
            self.current_file.set("Current file: Analysis stopped")
            self.write("dashboard", event.get("message", "Worker error"), "critical")
            messagebox.showerror("Error", event.get("message", "Worker error"))

    def apply_analysis_result(self, result):
        self.analysis_running = False

        if not result:
            self.status.set("DONE")
            self.progress.set(1)
            self.timer.set("Completed")
            return

        self.all_detections = list(result.get("all_detections", []))
        self.all_findings = [d.get("file_name", "UNKNOWN") for d in self.all_detections]
        self.fci_score = float(result.get("fci_score", 0))
        self.determination = result.get("determination", "")
        self.correlation_summary = result.get("correlation", {}).get("summary", "")
        self.timeline_data = result.get("timeline", {})
        self.report_path = result.get("report_path", "")

        for key in self.layer_data:
            self.layer_data[key] = []

        self.render_dashboard(result)
        self.render_layers(result.get("layer_results", {}))

        if self.timeline_data.get("events"):
            self.show_timeline()
        else:
            self.tabs["timeline"].delete("1.0", tk.END)
            self.tabs["timeline"].insert(tk.END, "No timeline data generated.\n", "normal")

        case_record = {
            "case_name": self.case_info.get("case_name", "Unknown"),
            "case_id": self.case_info.get("case_id", ""),
            "investigator": self.case_info.get("investigator", ""),
            "fci_score": self.fci_score,
            "determination": self.determination,
            "correlation_summary": self.correlation_summary,
            "artifact_count": len(self.all_detections),
            "date_completed": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        save_case(case_record)

        self.progress.set(1)
        self.status.set("DONE")
        self.timer.set("Completed")
        self.current_file.set("Current file: Completed")
        self.view_help.set(
            "Use Timeline Graph to see when events happened, Event Pie to see event-type distribution, and Relations to see which layers produced which artifacts."
        )

    def render_dashboard(self, result):
        tab = self.tabs["dashboard"]
        tab.delete("1.0", tk.END)

        tab.insert(tk.END, "TOR TRACE ANALYZER\n", "critical")
        tab.insert(tk.END, "MULTI-LAYER FORENSIC SUITE\n\n", "high")
        tab.insert(tk.END, "========== FORENSIC SUMMARY ==========\n\n", "high")

        total_artifacts = len(self.all_detections)
        active_layers = len([name for name, items in result.get("layer_results", {}).items() if items])

        if self.fci_score >= 70:
            risk = "HIGH"
        elif self.fci_score >= 40:
            risk = "MEDIUM"
        elif total_artifacts > 0:
            risk = "LOW"
        else:
            risk = "NONE"

        tab.insert(tk.END, f"FCI SCORE : {self.fci_score:.2f}%\n", "critical")
        tab.insert(tk.END, f"RISK LEVEL : {risk}\n", "critical")
        tab.insert(tk.END, f"ACTIVE LAYERS : {active_layers}\n", "medium")
        tab.insert(tk.END, f"DETECTIONS : {total_artifacts}\n", "artifact")
        tab.insert(
            tk.END,
            f"DETERMINATION : {self.determination or 'No determination generated'}\n",
            "high",
        )
        tab.insert(
            tk.END,
            f"CORRELATION : {self.correlation_summary or 'No cross-layer correlation found'}\n",
            "medium",
        )
        if self.report_path:
            tab.insert(tk.END, f"REPORT : {self.report_path}\n", "normal")

        tab.insert(tk.END, "\n========== DETECTED ARTIFACTS ==========\n\n", "high")
        if not self.all_detections:
            tab.insert(tk.END, "No detections were produced from the selected inputs.\n", "normal")
        else:
            for detection in self.all_detections:
                artifact_line = (
                    f"[{detection.get('layer', 'UNKNOWN')}] "
                    f"{detection.get('file_name', 'UNKNOWN')} -> "
                    f"{detection.get('message', 'No message')}"
                )
                tab.insert(tk.END, artifact_line + "\n", "artifact")

        if self.dashboard_messages:
            tab.insert(tk.END, "\n========== ENGINE MESSAGES ==========\n\n", "high")
            for message in self.dashboard_messages:
                self.write("dashboard", message, "normal")

        tab.see(tk.END)

    def render_layers(self, layer_results):
        for layer in ["memory", "system", "network", "application", "transport"]:
            tab = self.tabs[layer]
            tab.delete("1.0", tk.END)
            lines = []

            for detection in layer_results.get(layer, []):
                block = self.format_detection_block(detection)
                lines.extend(block)
                for line, tag in block:
                    tab.insert(tk.END, line + "\n", tag)

            if not lines:
                tab.insert(tk.END, "No detections in this layer.\n", "normal")

            self.layer_data[layer] = [line for line, _tag in lines]
            tab.see(tk.END)

    def format_detection_block(self, detection):
        timestamps = detection.get("disk_timestamps", {})
        lines = [
            (f"STATUS   : {detection.get('status', 'Detected')}", "artifact"),
            (f"ARTIFACT : {detection.get('file_name', 'UNKNOWN')}", "artifact"),
            (f"PATH     : {detection.get('file_path', 'N/A')}", "normal"),
            (f"EVIDENCE : {detection.get('evidence_match', 'N/A')}", "medium"),
            (f"MODIFIED : {timestamps.get('modified', 'N/A')}", "normal"),
            (f"CREATED  : {timestamps.get('created', 'N/A')}", "normal"),
            (f"ACCESSED : {timestamps.get('accessed', 'N/A')}", "normal"),
            (f"NOTE     : {detection.get('message', 'No message')}", "normal"),
            ("------------------------------", "normal"),
        ]
        return lines

    def write(self, tab, text, explicit_tag=None):
        widget = self.tabs.get(tab, self.tabs["dashboard"])
        tag = explicit_tag or "normal"

        if explicit_tag is None:
            if "CRITICAL" in text or "[!]" in text:
                tag = "critical"
            elif "HIGH" in text:
                tag = "high"
            elif "MEDIUM" in text:
                tag = "medium"
            elif "ARTIFACT" in text or "Detected" in text:
                tag = "artifact"

        display_text = text.replace("------------------------------", "-" * 30)
        widget.insert(tk.END, display_text + "\n", tag)
        widget.see(tk.END)

    def _tag_for_level(self, level):
        return {
            "error": "critical",
            "warning": "high",
            "info": "medium",
        }.get(level, "normal")

    def on_artifact_click(self, event):
        widget = event.widget
        index = widget.index(f"@{event.x},{event.y}")
        line = widget.get(f"{index} linestart", f"{index} lineend").strip()

        if not line:
            return

        for layer, lines in self.layer_data.items():
            if any(line in stored_line for stored_line in lines):
                self.jump_to_layer(layer, line)
                return

    def jump_to_layer(self, layer, keyword):
        if layer not in self.tabs:
            return

        self.tabview.set(layer.upper())
        tab = self.tabs[layer]
        tab.tag_remove("highlight", "1.0", tk.END)

        idx = tab.search(keyword, "1.0", nocase=1, stopindex=tk.END)
        if idx:
            end = f"{idx}+{len(keyword)}c"
            tab.tag_add("highlight", idx, end)
            tab.tag_config("highlight", background="yellow", foreground="black")
            tab.see(idx)

    def search_text(self):
        keyword = self.search_var.get()
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
                tab.tag_config("highlight", background="yellow", foreground="black")
                idx = end

    def show_graph(self):
        if not self.timeline_data.get("events"):
            messagebox.showwarning("Error", "Run analysis first")
            return

        self.graph_label.configure(text="Timeline Graph")
        self.view_help.set(
            "Timeline Graph: each dot is a reconstructed forensic event. Left side shows the forensic layer, bottom shows time."
        )
        plot_timeline_embedded(self.timeline_data, self.graph_canvas_frame)

    def show_pie_chart(self):
        if not self.timeline_data.get("events"):
            messagebox.showwarning("Error", "Run analysis first")
            return

        import matplotlib.pyplot as plt
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

        events = self.timeline_data.get("events", [])
        type_counts = {}
        for event in events:
            event_type = event.get("type", "UNKNOWN")
            type_counts[event_type] = type_counts.get(event_type, 0) + 1

        fig = plt.Figure(figsize=(6, 3))
        axis = fig.add_subplot(111)
        axis.pie(list(type_counts.values()), labels=list(type_counts.keys()), autopct="%1.1f%%")
        axis.set_title("Event Type Distribution")

        if self.graph_canvas:
            self.graph_canvas.get_tk_widget().destroy()

        self.graph_canvas = FigureCanvasTkAgg(fig, master=self.graph_canvas_frame)
        self.graph_canvas.draw()
        self.graph_canvas.get_tk_widget().pack(fill="both", expand=True)
        self.graph_label.configure(text="Event Pie")
        self.view_help.set(
            "Event Pie: shows how many timeline events were Modified, Created, Accessed, or flagged as Anomaly."
        )

    def show_timeline(self):
        tab = self.tabs["timeline"]
        tab.delete("1.0", tk.END)

        events = list(self.timeline_data.get("events", []))
        if not events:
            tab.insert(tk.END, "Timeline not generated.\n", "normal")
            return

        self.tabview.set("TIMELINE")

        filter_type = self.filter_var.get()
        start_raw = self.start_date.get()
        end_raw = self.end_date.get()

        try:
            start_dt = datetime.strptime(start_raw, "%Y-%m-%d") if start_raw else None
            end_dt = datetime.strptime(end_raw, "%Y-%m-%d") if end_raw else None
        except ValueError:
            start_dt = None
            end_dt = None

        def parse_time(value):
            if not value:
                return None
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue
            return None

        grouped = {}
        for event in events:
            event_type = event.get("type", "")
            if self.smart_mode and event_type not in {"ANOMALY", "MODIFIED"}:
                continue
            if filter_type != "ALL" and event_type != filter_type:
                continue

            time_value = event.get("time")
            parsed_time = parse_time(time_value)
            if not parsed_time:
                continue
            if start_dt and parsed_time < start_dt:
                continue
            if end_dt and parsed_time > end_dt:
                continue

            layer = event.get("layer", "UNKNOWN")
            artifact = event.get("artifact") or event.get("file_name") or "UNKNOWN"
            key = (time_value, layer, artifact)
            grouped.setdefault(key, []).append(event_type)

        for time_value, layer, artifact in sorted(grouped, key=lambda item: parse_time(item[0][0]) or datetime.max):
            tab.insert(tk.END, f"{time_value} | {layer} | {artifact}\n", "artifact")
            unique_types = list(dict.fromkeys(grouped[(time_value, layer, artifact)]))
            for event_type in unique_types:
                line = f"   -> {event_type} | {layer} | {artifact}"
                if event_type == "ANOMALY":
                    line += " | HIGH PRIORITY"
                tag = {
                    "ANOMALY": "critical",
                    "MODIFIED": "artifact",
                    "CREATED": "medium",
                    "ACCESSED": "high",
                }.get(event_type, "normal")
                tab.insert(tk.END, line + "\n", tag)
            tab.insert(tk.END, "\n", "normal")

        tab.see(tk.END)

    def build_detections(self):
        return list(self.all_detections)

    def toggle_smart(self):
        self.smart_mode = not self.smart_mode
        self.show_timeline()

    def show_relation(self):
        if not self.all_detections:
            messagebox.showwarning("Error", "Run analysis first")
            return

        self.graph_label.configure(text="Relations Map")
        self.view_help.set(
            "Relations: blue nodes are forensic layers, green nodes are detected artifacts, and each line shows which layer produced which artifact."
        )
        plot_relationship_embedded(self.all_detections, self.graph_canvas_frame)

    def show_view_guide(self):
        message = (
            "Timeline Graph:\n"
            "- Shows reconstructed events over time.\n"
            "- X-axis = date and time.\n"
            "- Y-axis = forensic layer (Memory, System, Network, Application, Transport).\n\n"
            "Event Pie:\n"
            "- Shows the percentage of event types in the timeline.\n"
            "- Modified, Created, Accessed, and Anomaly are counted.\n\n"
            "Relations:\n"
            "- Shows which forensic layer produced each artifact.\n"
            "- Blue nodes = layers, green nodes = detected artifacts.\n\n"
            "Start date / End date:\n"
            "- These do not change the scan itself.\n"
            "- They only filter what appears in the TIMELINE tab after analysis.\n"
            "- Use format YYYY-MM-DD, for example 2026-03-30."
        )
        messagebox.showinfo("How To Read The Views", message)

    def export(self):
        from report_generator import export_custom_report

        if not self.all_detections:
            messagebox.showwarning("Error", "Run analysis first")
            return

        file_types = [
            ("PDF Files", "*.pdf"),
            ("Text Files", "*.txt"),
            ("Excel Files", "*.xlsx"),
            ("CSV Files", "*.csv"),
            ("JSON Files", "*.json"),
        ]

        path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=file_types)
        if not path:
            return

        ext = os.path.splitext(path)[1].lower()
        if ext == ".pdf":
            format_type = "PDF"
        elif ext == ".txt":
            format_type = "TXT"
        elif ext == ".xlsx":
            format_type = "EXCEL"
        elif ext == ".csv":
            format_type = "CSV"
        elif ext == ".json":
            format_type = "JSON"
        else:
            format_type = "TXT"

        graph_path = get_temp_graph_path()
        plot_timeline(self.timeline_data, save_path=graph_path)

        notes = self.notes_box.get("1.0", tk.END).strip()
        case_info = {
            "case_name": self.case_info.get("case_name", "Unknown"),
            "case_id": self.case_info.get("case_id", ""),
            "investigator": self.case_info.get("investigator", ""),
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "graph_path": graph_path,
            "notes": notes,
        }

        export_custom_report(
            self.all_detections,
            self.fci_score,
            self.determination,
            self.correlation_summary,
            self.timeline_data,
            format_type,
            path,
            case_info,
            notes,
        )

        messagebox.showinfo("Success", f"Report saved:\n{path}")


if __name__ == "__main__":
    app = TorTraceGUI()
    app.mainloop()

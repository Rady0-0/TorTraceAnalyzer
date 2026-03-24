import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
import subprocess
import threading
import sys
import os
import time

# --- PYINSTALLER PATH HELPER ---
def get_resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class TorTraceGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("TorTrace Analyzer") 
        self.geometry("1400x950")
        
        # --- DATA STORAGE ---
        self.captured_detections = [] 
        self.last_fci = 0.0
        self.last_det = "Inconclusive"
        self.last_correlation = "No patterns identified."
        self.timeline_data = {"events": []}
        self.start_time = 0
        self.selected_paths = []

        # --- 1. STABLE BACKGROUND (Updated with Path Helper) ---
        try:
            bg_path = get_resource_path("bg_forensic.png")
            img = Image.open(bg_path)
            self.bg_image = ctk.CTkImage(light_image=img, dark_image=img, size=(1400, 950))
            self.bg_label = ctk.CTkLabel(self, image=self.bg_image, text="")
            self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        except: pass

        # --- 2. HEADER ---
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", pady=(40, 10))
        self.title_label = ctk.CTkLabel(header, text="TOR TRACE ANALYZER", 
                                       font=ctk.CTkFont(size=42, weight="bold"), text_color="#00d2ff")
        self.title_label.pack(expand=True)

        # --- 3. EXPORT HUD ---
        export_frame = ctk.CTkFrame(self, fg_color="transparent")
        export_frame.pack(anchor="e", padx=150)
        self.format_menu = ctk.CTkComboBox(export_frame, values=["TXT", "CSV", "EXCEL", "JSON"], width=100)
        self.format_menu.set("TXT")
        self.format_menu.pack(side="left", padx=10)
        self.export_btn = ctk.CTkButton(export_frame, text="📥 EXPORT", fg_color="#f78166", 
                                        command=self.handle_export, state="disabled", width=120)
        self.export_btn.pack(side="left")

        # --- 4. CONTROL PANEL ---
        panel = ctk.CTkFrame(self, fg_color="#0d1117", corner_radius=15, border_width=1, border_color="#30363d")
        panel.pack(fill="x", padx=150, pady=10)
        self.path_entry = ctk.CTkEntry(panel, width=450, height=40, placeholder_text="Awaiting Forensic Evidence...")
        self.path_entry.grid(row=0, column=0, padx=20, pady=20)
        ctk.CTkButton(panel, text="📁 FOLDER", command=self.add_folder, width=110).grid(row=0, column=1, padx=5)
        ctk.CTkButton(panel, text="📄 FILES", command=self.add_files, width=110, fg_color="#6f42c1").grid(row=0, column=2, padx=5)
        ctk.CTkButton(panel, text="RUN INVESTIGATION", command=self.start_analysis, 
                      fg_color="#00ffa3", text_color="black", font=ctk.CTkFont(weight="bold")).grid(row=0, column=3, padx=20)

        # --- 5. PROGRESS HUD ---
        hud = ctk.CTkFrame(self, fg_color="transparent")
        hud.pack(fill="x", padx=150, pady=5)
        self.progress_bar = ctk.CTkProgressBar(hud, width=800, height=12, progress_color="#00ffa3")
        self.progress_bar.set(0)
        self.progress_bar.pack(side="left", padx=(0, 20))
        self.time_label = ctk.CTkLabel(hud, text="Est. Time: --:--", font=("Consolas", 12))
        self.time_label.pack(side="right")

        # --- 6. TAB VIEW ---
        self.tabview = ctk.CTkTabview(self, width=1100, height=520, corner_radius=15, fg_color="#0d1117", border_width=1, border_color="#30363d")
        self.tabview.pack(pady=10, padx=150)
        self.tabs = {}
        for name in ["DASHBOARD", "MEMORY", "SYSTEM", "NETWORK", "APPLICATION", "TIMELINE"]:
            tab = self.tabview.add(name)
            txt = tk.Text(tab, bg="#0d1117", fg="#c9d1d9", font=("Consolas", 11), padx=20, pady=20, relief="flat", borderwidth=0, insertbackground="white")
            txt.pack(fill="both", expand=True)
            txt.tag_config("detected", foreground="#ff6b6b", font=("Consolas", 11, "bold"))
            txt.tag_config("evidence", foreground="#00ffa3")
            txt.tag_config("header", foreground="#00d2ff", font=("Consolas", 12, "bold"))
            self.tabs[name.lower()] = txt

        self.status_var = tk.StringVar(value="SYSTEM READY")
        ctk.CTkLabel(self, textvariable=self.status_var, text_color="#00ffa3").pack(side="bottom", anchor="w", padx=30, pady=10)

    def add_folder(self):
        f = filedialog.askdirectory()
        if f: self.selected_paths=[f]; self.path_entry.delete(0, tk.END); self.path_entry.insert(0, f)

    def add_files(self):
        f = filedialog.askopenfilenames()
        if f: self.selected_paths=list(f); self.path_entry.delete(0, tk.END); self.path_entry.insert(0, str(f))

    def start_analysis(self):
        if not self.selected_paths: return
        self.captured_detections = []
        self.timeline_data = {"events": []}
        for t in self.tabs.values(): t.delete("1.0", tk.END)
        self.start_time = time.time()
        self.progress_bar.set(0)
        self.status_var.set("ANALYSING ARTIFACTS...") 
        self.export_btn.configure(state="disabled")
        threading.Thread(target=self.run_engine, daemon=True).start()

    def run_engine(self):
        try:
            # FIX: We use the EXE itself as the interpreter and tell it to run main.py
            # The "Inception Fix" at the top of the file handles this routing.
            cmd = [sys.executable, "main.py"] + self.selected_paths
            
            # Added creationflags to hide the backend CMD window
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                text=True, 
                stderr=subprocess.STDOUT,
                creationflags=0x08000000 if os.name == 'nt' else 0 # CREATE_NO_WINDOW
            )
            
            curr_tab_key = "dashboard"
            temp_finding = {"disk_timestamps": {}}
            is_collecting_summary = False

            for line in process.stdout:
                if ">>> PROGRESS:" in line:
                    try:
                        val = int(line.split(":")[1].strip()) / 100
                        self.after(0, lambda v=val: self.progress_bar.set(v))
                        elapsed = time.time() - self.start_time
                        if val > 0:
                            total_est = elapsed / val
                            rem = max(0, int(total_est - elapsed))
                            self.after(0, lambda r=rem: self.time_label.configure(text=f"Est. Time: {r}s remaining"))
                    except: pass
                    continue

                if ">>> LAYER:" in line:
                    curr_tab_key = line.split(":")[1].strip().lower()
                    continue
                if ">>> END_LAYER" in line:
                    curr_tab_key = "dashboard"
                    is_collecting_summary = False
                    continue

                if "ARTIFACT :" in line: temp_finding["file_name"] = line.split(":")[1].strip()
                elif "PATH     :" in line: temp_finding["file_path"] = line.split(":")[1].strip()
                elif "EVIDENCE :" in line: temp_finding["evidence_match"] = line.split(":")[1].strip()
                elif "MODIFIED :" in line: temp_finding["disk_timestamps"]["modified"] = line.split(":")[1].strip()
                elif "CREATED  :" in line: temp_finding["disk_timestamps"]["created"] = line.split(":")[1].strip()
                elif "ACCESSED :" in line: temp_finding["disk_timestamps"]["accessed"] = line.split(":")[1].strip()
                elif "NOTE     :" in line: 
                    temp_finding["message"] = line.split(":")[1].strip()
                    temp_finding["layer"] = curr_tab_key.upper()
                    self.captured_detections.append(temp_finding.copy())
                    self.timeline_data["events"].append({
                        "modified": temp_finding["disk_timestamps"].get("modified", "N/A"),
                        "layer": curr_tab_key.upper(),
                        "file": temp_finding["file_name"],
                        "anomaly": "" 
                    })
                    temp_finding = {"disk_timestamps": {}}

                if "FORENSIC CONFIDENCE INDEX" in line:
                    score_str = line.split(":")[1].strip().replace("%", "")
                    self.last_fci = float(score_str)
                if "INVESTIGATIVE DETERMINATION" in line:
                    self.last_det = line.split(":")[1].strip()
                if "[FORENSIC CORRELATION SUMMARY]:" in line:
                    is_collecting_summary = True
                    self.last_correlation = ""
                    continue
                
                if is_collecting_summary and line.strip() and "=" not in line:
                    self.last_correlation += line.strip() + " "

                self.after(0, self.update_terminal, curr_tab_key, line)

            process.wait()
            self.after(0, lambda: self.status_var.set("INVESTIGATION COMPLETE"))
            self.after(0, lambda: self.export_btn.configure(state="normal"))
            self.after(0, lambda: self.time_label.configure(text="SCAN COMPLETE"))
            
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Engine Error", str(e)))

    def update_terminal(self, tab_key, text):
        tag = None
        if "DETECTED" in text.upper() or "HIGH:" in text.upper() or "CRITICAL:" in text.upper():
            tag = "detected"
        elif "EVIDENCE :" in text.upper():
            tag = "evidence"
        elif ">>> LAYER:" in text or "=" in text:
            tag = "header"

        if tab_key in self.tabs and tab_key != "dashboard":
            self.tabs[tab_key].insert(tk.END, text, tag)
            self.tabs[tab_key].see(tk.END)
        
        self.tabs["dashboard"].insert(tk.END, text, tag)
        self.tabs["dashboard"].see(tk.END)

    def handle_export(self):
        from report_generator import export_custom_report
        fmt = self.format_menu.get()
        target = filedialog.asksaveasfilename(defaultextension=f".{fmt.lower()}", 
                                             initialfile=f"TorTrace_Export_{int(time.time())}")
        if target:
            success = export_custom_report(
                self.captured_detections, 
                self.last_fci, 
                self.last_det, 
                self.last_correlation, 
                self.timeline_data, 
                fmt, 
                target
            )
            if success: 
                messagebox.showinfo("Success", f"Evidence archived as {fmt}")
            else:
                messagebox.showerror("Export Error", "Check console. Ensure 'openpyxl' is installed for Excel.")

# --- THE INCEPTION FIX ---
# This block intercepts the call when the EXE tries to launch itself 
# to run the backend analysis. It prevents the infinite GUI loop.
if __name__ == "__main__":
    if len(sys.argv) > 1 and "main.py" in sys.argv[1]:
        import main
        main.main()
    else:
        app = TorTraceGUI()
        app.mainloop()
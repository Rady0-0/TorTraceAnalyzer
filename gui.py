import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk 
import subprocess
import threading
import sys
import os
import multiprocessing

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class TorTraceGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("TorTraceAnalyzer - Professional Forensic Suite")
        self.geometry("1400x900")
        self.accent_blue = "#00d2ff"
        self.accent_green = "#00ffa3"
        self.selected_paths = []

        try:
            img_path = self.resource_path("bg_forensic.png")
            self.raw_bg = Image.open(img_path) 
            self.bg_photo = ctk.CTkImage(self.raw_bg, size=(1400, 900))
            self.bg_label = ctk.CTkLabel(self, image=self.bg_photo, text="")
            self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            self.bind("<Configure>", self.resize_background)
        except: pass

        # UI Components
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", pady=(30, 10))
        ctk.CTkLabel(header_frame, text="TOR TRACE ANALYZER", font=ctk.CTkFont(size=38, weight="bold"), text_color=self.accent_blue).pack(side="left", padx=(450, 0))
        self.export_btn = ctk.CTkButton(header_frame, text="📥 EXPORT REPORT", fg_color="#f78166", command=self.export_report, state="disabled")
        self.export_btn.pack(side="right", padx=40)

        panel = ctk.CTkFrame(self, fg_color=("#161c24", "#0d1117"), corner_radius=15, border_width=1, border_color="#30363d")
        panel.pack(fill="x", padx=150, pady=20)
        self.path_entry = ctk.CTkEntry(panel, width=450, height=40, placeholder_text="Awaiting Forensic Evidence...")
        self.path_entry.grid(row=0, column=0, padx=(20, 10), pady=20)
        ctk.CTkButton(panel, text="📁 FOLDER", command=self.add_folder, width=120).grid(row=0, column=1, padx=5)
        ctk.CTkButton(panel, text="📄 FILES", command=self.add_files, width=120, fg_color="#6f42c1").grid(row=0, column=2, padx=5)
        ctk.CTkButton(panel, text="RUN INVESTIGATION", command=self.start_analysis, fg_color=self.accent_green, text_color="black", font=ctk.CTkFont(weight="bold")).grid(row=0, column=3, padx=20)

        self.tabview = ctk.CTkTabview(self, width=1100, height=550, corner_radius=15, fg_color="#0d1117", border_width=1, border_color="#30363d")
        self.tabview.pack(pady=(10, 30), padx=150)
        self.tabs = {}
        for name in ["DASHBOARD", "MEMORY LAYER", "SYSTEM LAYER", "NETWORK LAYER", "APPLICATION LAYER", "TIMELINE"]:
            tab = self.tabview.add(name)
            txt = tk.Text(tab, bg="#0d1117", fg="#c9d1d9", font=("Consolas", 11), padx=20, pady=20, relief="flat", borderwidth=0, insertbackground="white")
            txt.pack(fill="both", expand=True)
            txt.tag_config("detected", foreground="#ff6b6b", font=("Consolas", 11, "bold"))
            txt.tag_config("timestamp", foreground="#f1fa8c")
            txt.tag_config("layer_head", foreground=self.accent_blue, font=("Consolas", 12, "bold")) # BLUE HEADERS
            self.tabs[name.split()[0].lower()] = txt

        self.status_var = tk.StringVar(value="SYSTEM READY")
        ctk.CTkLabel(self, textvariable=self.status_var, text_color=self.accent_green, font=ctk.CTkFont(size=12, weight="bold")).pack(side="bottom", anchor="w", padx=30, pady=10)

    def resource_path(self, relative_path):
        try: base_path = sys._MEIPASS
        except: base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)

    def resize_background(self, event):
        if hasattr(self, 'bg_photo'): self.bg_photo.configure(size=(event.width, event.height))

    def add_folder(self):
        f = filedialog.askdirectory()
        if f: self.selected_paths=[f]; self.path_entry.delete(0, tk.END); self.path_entry.insert(0, f)

    def add_files(self):
        f = filedialog.askopenfilenames()
        if f: self.selected_paths=list(f); self.path_entry.delete(0, tk.END); self.path_entry.insert(0, str(f))

    def start_analysis(self):
        if not self.selected_paths: return
        for t in self.tabs.values(): t.delete("1.0", tk.END)
        self.status_var.set("ANALYZING ARTIFACTS...")
        threading.Thread(target=self.run_engine, daemon=True).start()

    def run_engine(self):
        try:
            cmd = [sys.executable, "main.py"] + self.selected_paths
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            
            curr_tab = None
            for line in process.stdout:
                # 1. Logic for Routing (Hidden from User)
                if ">>> LAYER:" in line:
                    key = line.split(":")[1].strip().split()[0].lower()
                    curr_tab = self.tabs.get(key)
                    continue
                if ">>> END_LAYER" in line:
                    curr_tab = None
                    continue

                # 2. Logic for Coloring
                tag = None
                if any(x in line.upper() for x in ["CRITICAL", "ARTIFACT", "DETECTED"]):
                    tag = "detected"
                elif "[ LAYER:" in line.upper(): # New Blue Tag for Layer Names
                    tag = "layer_head"
                elif " • " in line:
                    tag = "timestamp"

                # 3. Always print to Dashboard (Master Log)
                self.tabs["dashboard"].insert(tk.END, line, tag)
                self.tabs["dashboard"].see(tk.END)

                # 4. Print to specific layer tabs (Excluding redundant Dashboard insert)
                if curr_tab and curr_tab != self.tabs["dashboard"]:
                    curr_tab.insert(tk.END, line, tag)
                    curr_tab.see(tk.END)
            
            process.wait()
            self.status_var.set("INVESTIGATION COMPLETE")
            self.export_btn.configure(state="normal")
            messagebox.showinfo("Analysis Complete", "Forensic master log updated.")
        except Exception as e: messagebox.showerror("Error", str(e))

    def export_report(self):
        files = [f for f in os.listdir('.') if f.startswith('TorTrace_Forensic_Report')]
        if not files: return
        latest = sorted(files)[-1]
        save = filedialog.asksaveasfilename(defaultextension=".txt")
        if save: os.replace(latest, save); messagebox.showinfo("Saved", "Report exported.")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    if len(sys.argv) > 1 and sys.argv[1] == "main.py":
        import main
        sys.argv = [sys.argv[0]] + sys.argv[2:] 
        main.main()
    else:
        app = TorTraceGUI()
        app.mainloop()
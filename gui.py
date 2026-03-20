import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk 
import subprocess
import threading
import sys
import os

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

        # 1. DYNAMIC BACKGROUND
        try:
            self.raw_bg = Image.open("bg_forensic.png") 
            self.bg_photo = ctk.CTkImage(self.raw_bg, size=(1400, 900))
            self.bg_label = ctk.CTkLabel(self, image=self.bg_photo, text="")
            self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            self.bind("<Configure>", self.resize_background)
        except Exception as e:
            print(f"[!] Background error: {e}")

        # 2. HEADER
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.pack(fill="x", pady=(30, 10))

        self.header_label = ctk.CTkLabel(self.header_frame, text="TOR TRACE ANALYZER", 
                                         font=ctk.CTkFont(size=38, weight="bold"),
                                         text_color=self.accent_blue)
        self.header_label.pack(side="left", padx=(450, 0))

        self.export_btn = ctk.CTkButton(self.header_frame, text="📥 EXPORT REPORT", 
                                        fg_color="#f78166", hover_color="#d66a54",
                                        text_color="white", font=ctk.CTkFont(size=12, weight="bold"),
                                        command=self.export_report, state="disabled")
        self.export_btn.pack(side="right", padx=40)

        # 3. INPUT PANEL
        self.panel = ctk.CTkFrame(self, fg_color=("#161c24", "#0d1117"), 
                                  corner_radius=15, border_width=1, border_color="#30363d")
        self.panel.pack(fill="x", padx=150, pady=20)

        self.path_entry = ctk.CTkEntry(self.panel, width=450, height=40, placeholder_text="Awaiting Forensic Evidence...")
        self.path_entry.grid(row=0, column=0, padx=(20, 10), pady=20)

        self.btn_folder = ctk.CTkButton(self.panel, text="📁 FOLDER", command=self.add_folder, 
                                        fg_color="#1f6feb", width=120)
        self.btn_folder.grid(row=0, column=1, padx=5)

        self.btn_files = ctk.CTkButton(self.panel, text="📄 FILES", command=self.add_files, 
                                       fg_color="#6f42c1", width=120)
        self.btn_files.grid(row=0, column=2, padx=5)

        self.btn_run = ctk.CTkButton(self.panel, text="RUN INVESTIGATION", command=self.start_analysis, 
                                     fg_color=self.accent_green, text_color="black", 
                                     font=ctk.CTkFont(weight="bold"), width=160)
        self.btn_run.grid(row=0, column=3, padx=20)

        # 4. TABBED OUTPUT (Using standard tk.Text for coloring)
        self.tabview = ctk.CTkTabview(self, width=1100, height=550, corner_radius=15, 
                                      fg_color="#0d1117", border_width=1, border_color="#30363d")
        self.tabview.pack(pady=(10, 30), padx=150)
        
        self.tabs = {}
        tab_list = ["DASHBOARD", "MEMORY LAYER", "SYSTEM LAYER", "NETWORK LAYER", "APPLICATION LAYER", "TIMELINE"]
        for name in tab_list:
            tab = self.tabview.add(name)
            # Use raw tk.Text for forensic coloring tags
            txt = tk.Text(tab, bg="#0d1117", fg="#c9d1d9", font=("Consolas", 11), 
                          padx=20, pady=20, relief="flat", borderwidth=0, insertbackground="white")
            txt.pack(padx=5, pady=5, fill="both", expand=True)
            
            # Forensic Highlighting Tags
            txt.tag_config("detected", foreground="#ff6b6b", font=("Consolas", 11, "bold"))
            txt.tag_config("timestamp", foreground="#f1fa8c")
            txt.tag_config("header", foreground=self.accent_blue, font=("Consolas", 12, "bold"))
            
            key = name.split()[0].lower()
            self.tabs[key] = txt

        # 5. STATUS BAR (FIXED THE .SET ERROR)
        self.status_var = tk.StringVar(value="SYSTEM READY")
        self.status_label = ctk.CTkLabel(self, textvariable=self.status_var, 
                                         text_color=self.accent_green, font=ctk.CTkFont(size=12, weight="bold"))
        self.status_label.pack(side="bottom", anchor="w", padx=30, pady=10)

    def resize_background(self, event):
        if hasattr(self, 'bg_photo'):
            self.bg_photo.configure(size=(event.width, event.height))

    def add_folder(self):
        folder = filedialog.askdirectory()
        if folder: self.selected_paths = [folder]; self.path_entry.delete(0, tk.END); self.path_entry.insert(0, folder)

    def add_files(self):
        files = filedialog.askopenfilenames()
        if files: self.selected_paths = list(files); self.path_entry.delete(0, tk.END); self.path_entry.insert(0, str(files))

    def start_analysis(self):
        if not self.selected_paths: return
        for t in self.tabs.values(): t.delete("1.0", tk.END) # Clear old data
        self.status_var.set("ANALYZING ARTIFACTS...") # FIXED: Using .set on StringVar
        threading.Thread(target=self.run_engine, daemon=True).start()

    def run_engine(self):
        try:
            cmd = [sys.executable, "main.py"] + self.selected_paths
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, stderr=subprocess.STDOUT)
            
            curr_tab = None
            for line in process.stdout:
                # Dashboard always gets the full feed
                self.tabs["dashboard"].insert(tk.END, line)
                self.tabs["dashboard"].see(tk.END)

                # Routing and Coloring
                if ">>> LAYER:" in line:
                    key = line.split(":")[1].strip().split()[0].lower()
                    curr_tab = self.tabs.get(key)
                    continue
                elif ">>> END_LAYER" in line:
                    if curr_tab: curr_tab.insert(tk.END, "\n" + "-"*50 + "\n\n") # Added Spacing
                    curr_tab = None
                    continue

                if curr_tab:
                    tag = None
                    if "ARTIFACT" in line.upper(): tag = "detected"
                    elif " • " in line or "OCCURRED" in line: tag = "timestamp"
                    
                    curr_tab.insert(tk.END, line, tag)
                    curr_tab.see(tk.END)
            
            process.wait()
            self.status_var.set("INVESTIGATION COMPLETE") # FIXED
            self.export_btn.configure(state="normal")
            messagebox.showinfo("Forensic Analysis", "Investigation finalized. Artifacts sorted and highlighted.")
        except Exception as e:
            messagebox.showerror("Engine Error", str(e))

    def export_report(self):
        report_files = [f for f in os.listdir('.') if f.startswith('TorTrace_Forensic_Report')]
        if not report_files: return
        latest_report = sorted(report_files)[-1]
        save_path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="Evidence_Report.txt")
        if save_path:
            import shutil
            shutil.copy(latest_report, save_path)
            messagebox.showinfo("Export Success", f"Report saved to {save_path}")

if __name__ == "__main__":
    app = TorTraceGUI()
    app.mainloop()
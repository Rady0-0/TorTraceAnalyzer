import tkinter as tk
from tkinter import filedialog
import subprocess
import threading
import os
import json
import csv

selected_paths = []

# ===============================
# MAIN WINDOW
# ===============================

root = tk.Tk()
root.title("TorTraceAnalyzer - Darknet Forensic Investigation Tool")
root.geometry("1100x720")
root.configure(bg="#0b1a2b")

# ===============================
# TITLE
# ===============================

title = tk.Label(
    root,
    text="TorTraceAnalyzer",
    font=("Segoe UI", 30, "bold"),
    fg="#3fb7ff",
    bg="#0b1a2b"
)
title.pack(pady=10)

subtitle = tk.Label(
    root,
    text="Multi-Layer Darknet Forensic Detection System",
    font=("Segoe UI", 12),
    fg="white",
    bg="#0b1a2b"
)
subtitle.pack()

# ===============================
# INPUT SECTION
# ===============================

frame = tk.Frame(root, bg="#0b1a2b")
frame.pack(pady=15)

input_box = tk.Entry(frame, width=70, font=("Segoe UI",10))
input_box.grid(row=0,column=0,padx=10)

def select_folder():
    folder = filedialog.askdirectory()
    if folder:
        selected_paths.append(folder)
        input_box.delete(0,tk.END)
        input_box.insert(0,folder)

def select_files():
    files = filedialog.askopenfilenames()
    if files:
        selected_paths.extend(files)
        input_box.delete(0,tk.END)
        input_box.insert(0,", ".join(files))

tk.Button(frame,text="Select Folder",bg="#1f6feb",fg="white",
          command=select_folder,width=15).grid(row=0,column=1,padx=5)

tk.Button(frame,text="Select Files",bg="#6f42c1",fg="white",
          command=select_files,width=15).grid(row=0,column=2,padx=5)

# ===============================
# SUMMARY PANEL
# ===============================

summary_frame = tk.Frame(root,bg="#12344d",height=100)
summary_frame.pack(fill="x",padx=20,pady=10)

summary_title = tk.Label(summary_frame,
                         text="Investigation Summary",
                         font=("Segoe UI",12,"bold"),
                         fg="white",
                         bg="#12344d")
summary_title.pack()

summary_text = tk.Label(summary_frame,
                        text="No analysis yet",
                        fg="white",
                        bg="#12344d",
                        font=("Segoe UI",10))
summary_text.pack()

# ===============================
# RESULT WINDOW
# ===============================

frame2 = tk.Frame(root)
frame2.pack()

scroll = tk.Scrollbar(frame2)

output = tk.Text(
    frame2,
    width=120,
    height=25,
    bg="#020c1b",
    fg="white",
    insertbackground="white",
    font=("Consolas",11),
    spacing2=3,
    yscrollcommand=scroll.set
)

scroll.config(command=output.yview)
scroll.pack(side=tk.RIGHT,fill=tk.Y)
output.pack()

# COLOR TAGS
output.tag_config("red",foreground="#ff4d4d")
output.tag_config("green",foreground="#00ff9c")
output.tag_config("yellow",foreground="#ffd166")

# ===============================
# STATUS BAR
# ===============================

status = tk.Label(root,
                  text="STATUS: READY",
                  bg="#0b1a2b",
                  fg="lightgreen")
status.pack(pady=5)

# ===============================
# EXPORT REPORT
# ===============================

def export_report():

    if not os.path.exists("tortrace_report.txt"):
        status.config(text="No report found to export", fg="red")
        return

    filetypes = [
        ("Text File", "*.txt"),
        ("JSON File", "*.json"),
        ("CSV File", "*.csv")
    ]

    save_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=filetypes
    )

    if not save_path:
        return

    with open("tortrace_report.txt", "r") as f:
        content = f.read()

    ext = os.path.splitext(save_path)[1]

    if ext == ".txt":

        with open(save_path,"w") as f:
            f.write(content)

    elif ext == ".json":

        data = {"report": content.split("\n")}

        with open(save_path,"w") as f:
            json.dump(data,f,indent=4)

    elif ext == ".csv":

        lines = content.split("\n")

        with open(save_path,"w",newline="") as f:
            writer = csv.writer(f)
            for line in lines:
                writer.writerow([line])

    status.config(text="Report exported successfully", fg="lightgreen")


export_btn = tk.Button(
    root,
    text="Export Report",
    command=export_report,
    bg="#f78166",
    fg="white",
    width=20
)

export_btn.pack(pady=5)

# ===============================
# SUMMARY GENERATION
# ===============================

def generate_summary(out):

    mem="Not Detected"
    sys="Not Detected"
    net="Not Detected"
    app="Not Detected"

    if "[Memory Layer] Tor process detected" in out:
        mem="Detected"

    if "[System Layer] Tor execution artifacts detected" in out:
        sys="Detected"

    if "[Network Layer] Tor network indicators detected" in out:
        net="Detected"

    if "[Application Layer] Tor browser artifacts detected" in out:
        app="Detected"

    text=f"""
Memory Layer : {mem}
System Layer : {sys}
Network Layer : {net}
Application Layer : {app}
"""

    summary_text.config(text=text)

# ===============================
# COLOR RESULT OUTPUT
# ===============================

def insert_colored(text):

    for line in text.splitlines():

        if "detected" in line.lower():
            output.insert(tk.END,line+"\n","red")

        elif "no tor" in line.lower():
            output.insert(tk.END,line+"\n","green")

        else:
            output.insert(tk.END,line+"\n")

# ===============================
# RUN ANALYSIS
# ===============================

def run_analysis():

    status.config(text="STATUS: ANALYZING...",fg="yellow")

    def task():

        try:

            cmd=["python","main.py"]+selected_paths

            result=subprocess.run(cmd,capture_output=True,text=True)

            output.delete(1.0,tk.END)

            insert_colored(result.stdout)

            generate_summary(result.stdout)

        except Exception as e:
            output.insert(tk.END,str(e))

        status.config(text="STATUS: ANALYSIS COMPLETE",fg="lightgreen")

    threading.Thread(target=task).start()

tk.Button(frame,text="Run Analysis",command=run_analysis,
          bg="#2ea043",fg="white",width=15).grid(row=0,column=3,padx=5)

# ===============================
# START GUI
# ===============================

root.mainloop()
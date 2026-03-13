import os
import sys
import csv
import json

from memory_analysis import check_memory
from system_analysis import check_system
from network_analysis import check_network
from application_analysis import check_application
from artifact_correlation import correlate_artifacts
from timeline_reconstruction import build_timeline
from risk_scoring import calculate_risk
from report_generator import generate_report


def read_file(file):

    ext = os.path.splitext(file)[1].lower()

    try:

        if ext in [".txt", ".log"]:
            with open(file, "r", errors="ignore") as f:
                return f.read().lower()

        elif ext == ".csv":
            data = ""
            with open(file, newline='', errors="ignore") as f:
                reader = csv.reader(f)
                for row in reader:
                    data += " ".join(row).lower()
            return data

        elif ext == ".json":
            with open(file, "r", errors="ignore") as f:
                return json.dumps(json.load(f)).lower()

        else:
            return ""

    except:
        return ""


print("\n========================================")
print("      TORTRACEANALYZER INVESTIGATION")
print("========================================\n")


# -------- INPUT COLLECTION --------

inputs = sys.argv[1:]

files = []

for path in inputs:

    if os.path.isdir(path):
        for f in os.listdir(path):
            files.append(os.path.join(path, f))

    elif os.path.isfile(path):
        files.append(path)


# -------- FILE CLASSIFICATION --------

memory_files = []
system_files = []
network_files = []
application_files = []

for filepath in files:

    if os.path.isfile(filepath):

        data = read_file(filepath)

        if any(x in data for x in ["tor.exe", "firefox.exe", "pid"]):
            memory_files.append(filepath)

        if any(x in data for x in ["prefetch", ".pf", "tor.exe.pf", "firefox.exe.pf"]):
            system_files.append(filepath)

        if any(x in data for x in ["tls", "9050", "socks", "relay"]):
            network_files.append(filepath)

        if any(x in data for x in ["places.sqlite", "cookies.sqlite", "tor browser"]):
            application_files.append(filepath)


# -------- RESULT FLAGS --------

results = {
    "memory": False,
    "system": False,
    "network": False,
    "application": False
}


# -------- MEMORY ANALYSIS --------

print("MEMORY ANALYSIS")
print("--------------------------------")

memory_artifacts = set()

for f in memory_files:

    result = check_memory(f)

    if "detected" in result.lower():

        artifacts = result.split(":")[-1].strip().split(",")

        for a in artifacts:
            memory_artifacts.add(a.strip())

if memory_artifacts:

    print("[Memory Layer] Tor process detected:", ", ".join(memory_artifacts))
    results["memory"] = True

else:

    print("[Memory Layer] No Tor process detected")


# -------- SYSTEM ANALYSIS --------

print("\nSYSTEM ANALYSIS")
print("--------------------------------")

if not system_files:
    print("[System Layer] No Tor execution artifacts detected")

for f in system_files:

    result = check_system(f)
    print(result)

    if "detected" in result.lower():
        results["system"] = True


# -------- NETWORK ANALYSIS --------

print("\nNETWORK ANALYSIS")
print("--------------------------------")

if not network_files:
    print("[Network Layer] No Tor network indicators detected")

for f in network_files:

    result = check_network(f)
    print(result)

    if "detected" in result.lower():
        results["network"] = True


# -------- APPLICATION ANALYSIS --------

print("\nAPPLICATION ANALYSIS")
print("--------------------------------")

if not application_files:
    print("[Application Layer] No Tor browser artifacts detected")

for f in application_files:

    result = check_application(f)
    print(result)

    if "detected" in result.lower():
        results["application"] = True


# -------- ARTIFACT CORRELATION --------

print("\n========================================")
print("         ARTIFACT CORRELATION")
print("========================================\n")

correlation = correlate_artifacts(results)

for c in correlation["correlations"]:
    print("•", c)


# -------- Timeline Reconstruction --------

print("\n========================================")
print("         ACTIVITY TIMELINE")
print("========================================\n")

timeline_data = build_timeline(results)

print("Detected Timeline Events:\n")

for event in timeline_data["timeline"]:
    print("•", event)

print("\nTimeline Reconstruction:\n")

for step in timeline_data["reconstruction"]:
    print("•", step)


# -------- RISK SCORING --------

print("\n========================================")
print("            RISK ASSESSMENT")
print("========================================\n")

score, level = calculate_risk(results)

print("TOR ACTIVITY RISK SCORE:", score)
print("CONFIDENCE LEVEL:", level)


# -------- REPORT GENERATION --------

generate_report(results, correlation["correlations"], score, level)


print("\n========================================")
print("           ANALYSIS COMPLETE")
print("========================================")
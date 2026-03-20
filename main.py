import sys
import os
import re
from datetime import datetime

# --- CORE FORENSIC MODULES ---
from file_parser import parse_forensic_file
from memory_analysis import check_memory
from system_analysis import check_system
from network_analysis import check_network
from application_analysis import check_application

# --- CORRELATION & REPORTING ---
from artifact_correlation import correlate_artifacts
from timeline_reconstruction import build_timeline
from risk_scoring import calculate_fci
from report_generator import generate_report

def resource_path(relative_path):
    """ Get absolute path to resource for PyInstaller EXE compatibility """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def main():
    # 1. EVIDENCE INGESTION
    inputs = sys.argv[1:]
    if not inputs:
        print("[!] ERROR: No forensic sources selected for analysis.")
        return

    evidence_files = []
    for path in inputs:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for f in files: evidence_files.append(os.path.join(root, f))
        elif os.path.isfile(path):
            evidence_files.append(path)

    # Header Prints (Sent to Dashboard by default)
    print(">>> LAYER: DASHBOARD")
    print("="*65)
    print(f"{'TOR TRACE ANALYZER - MULTI-LAYER FORENSIC SUITE':^65}")
    print(f"{'Started: ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'):^65}")
    print("="*65 + "\n")
    print(">>> END_LAYER")

    all_detections = []
    layer_hits = {"memory": False, "system": False, "network": False, "application": False}

    # 2. MULTI-HIT ANALYSIS LOOP
    for f_path in evidence_files:
        try:
            parsed_data = parse_forensic_file(f_path)
            
            layers = [
                ("MEMORY", check_memory), ("SYSTEM", check_system),
                ("NETWORK", check_network), ("APPLICATION", check_application)
            ]

            for name, func in layers:
                results = func(parsed_data)
                
                if results: # Only print if something was actually found
                    print(f">>> LAYER: {name.upper()}")
                    for result in results:
                        if result.get("status") == "Detected":
                            all_detections.append(result)
                            layer_hits[name.lower()] = True
                            
                            print(f"    STATUS   : DETECTED")
                            print(f"    ARTIFACT : {result['file_name']}")
                            print(f"    PATH     : {result['file_path']}")
                            print(f"    OCCURRED : {result['disk_timestamps'].get('modified', 'N/A')}")
                            print(f"    NOTE     : {result['message']}")
                            print("-" * 30)
                    print(f">>> END_LAYER\n")
        except Exception as e:
            print(f"[!] Error processing {f_path}: {e}")

    # 3. BEHAVIORAL PATTERN CORRELATION (Sent to Dashboard)
    correlation = correlate_artifacts(layer_hits, all_detections)
    
    # 4. CHRONOLOGICAL TIMELINE RECONSTRUCTION
    timeline = build_timeline(all_detections)

    # 5. CONFIDENCE SCORING & FINAL SUMMARY
    fci_score, determination = calculate_fci(layer_hits)

    # ROUTE FINAL RESULTS TO DASHBOARD TAB
    print(">>> LAYER: DASHBOARD")
    print(f"\n[FORENSIC CORRELATION SUMMARY]:\n{correlation['summary']}\n")
    print(f"FORENSIC CONFIDENCE INDEX (FCI): {fci_score:.1f}%")
    print(f"INVESTIGATIVE DETERMINATION: {determination}")
    print("\n" + "="*65)
    print(">>> END_LAYER")

    # ROUTE TIMELINE TO TIMELINE TAB
    print(">>> LAYER: TIMELINE")
    print(f"{'TIMESTAMP':<22} | {'LAYER':<12} | {'ARTIFACT'}")
    print("-" * 65)
    for event in timeline["events"]:
        print(f" • {event['time']:<20} | {event['layer']:<12} | {event['file']}")
    print(">>> END_LAYER\n")

    # Generate Report
    report_path = generate_report(all_detections, fci_score, determination, layer_hits)
    
    # Final Notification
    print(">>> LAYER: DASHBOARD")
    print(f"\n[*] Formal Evidence Report generated: {report_path}")
    print("[!] INVESTIGATION COMPLETE")
    print(">>> END_LAYER")

# No GUI code here! 
if __name__ == "__main__":
    main()
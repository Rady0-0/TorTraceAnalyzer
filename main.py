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

def main():
    inputs = sys.argv[1:]
    if not inputs:
        print("[!] ERROR: No forensic sources selected.")
        return

    evidence_files = []
    for path in inputs:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for f in files: evidence_files.append(os.path.join(root, f))
        elif os.path.isfile(path):
            evidence_files.append(path)

    # 1. HEADER (Sent to Dashboard)
    print(">>> LAYER: DASHBOARD")
    print("="*65)
    print(f"{'TOR TRACE ANALYZER - MULTI-LAYER FORENSIC SUITE':^65}")
    print(f"{'Started: ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'):^65}")
    print("="*65 + "\n")
    print(">>> END_LAYER")
    sys.stdout.flush()

    all_detections = []
    layer_hits = {"memory": False, "system": False, "network": False, "application": False}
    total_files = len(evidence_files)

    # 2. ANALYSIS LOOP
    for i, f_path in enumerate(evidence_files):
        try:
            # PROGRESS SIGNAL (Requirement 6: Real-time HUD)
            progress = int(((i + 1) / total_files) * 100)
            print(f">>> PROGRESS: {progress}")
            sys.stdout.flush() 

            parsed_data = parse_forensic_file(f_path)
            e_type = parsed_data.get("evidence_type", "DISK")
            
            # --- UPDATED ROUTING LOGIC ---
            # This ensures Network logs (Wireshark) actually trigger the Network Layer
            if e_type == "MEMORY":
                active_layers = [("MEMORY", check_memory), ("NETWORK", check_network)]
            elif e_type == "NETWORK":
                active_layers = [("NETWORK", check_network)]
            else: # DISK (Images/Autopsy)
                # We include Network here too because Disk images contain IP/Port logs
                active_layers = [("SYSTEM", check_system), ("APPLICATION", check_application), ("NETWORK", check_network)]

            for name, func in active_layers:
                results = func(parsed_data)
                if results:
                    print(f">>> LAYER: {name.upper()}")
                    for result in results:
                        if result.get("status") == "Detected":
                            all_detections.append(result)
                            layer_hits[name.lower()] = True
                            
                            # REQUIREMENT 4: Definitive Evidence Printing
                            print(f"    STATUS   : DETECTED")
                            print(f"    ARTIFACT : {result['file_name']}")
                            print(f"    PATH     : {result['file_path']}")
                            print(f"    EVIDENCE : {result.get('evidence_match', 'N/A')}")
                            
                            # REQUIREMENT 1: Full MACB Metadata Display
                            ts = result['disk_timestamps']
                            print(f"    MODIFIED : {ts.get('modified', 'N/A')}")
                            print(f"    CREATED  : {ts.get('created', 'N/A')}")
                            print(f"    ACCESSED : {ts.get('accessed', 'N/A')}")
                            
                            print(f"    NOTE     : {result['message']}")
                            print("-" * 30)
                    print(f">>> END_LAYER\n")
                    sys.stdout.flush()

        except Exception as e:
            print(f">>> LAYER: DASHBOARD\n[!] Error processing {os.path.basename(f_path)}: {e}\n>>> END_LAYER")
            sys.stdout.flush()

    # 3. CORE CALCULATIONS
    # We must generate the correlation AND the timeline before the report can be made
    correlation = correlate_artifacts(layer_hits, all_detections)
    timeline = build_timeline(all_detections) 
    fci_score, determination = calculate_fci(layer_hits, all_detections)

    # 4. FINAL DASHBOARD OUTPUT
    print(">>> LAYER: DASHBOARD")
    print(f"\n[FORENSIC CORRELATION SUMMARY]:\n{correlation['summary']}\n")
    print(f"FORENSIC CONFIDENCE INDEX (FCI): {fci_score:.1f}%")
    print(f"INVESTIGATIVE DETERMINATION: {determination}")
    print("\n" + "="*65)
    print(">>> END_LAYER")
    sys.stdout.flush()

    # 5. TIMELINE OUTPUT (Requirement 1: Chronological MACB)
    print(">>> LAYER: TIMELINE")
    print(f"{'TIMESTAMP (MODIFIED)':<22} | {'LAYER':<12} | {'ARTIFACT'}")
    print("-" * 65)
    
    # We use the 'events' list from our timeline object for the dashboard display
    for event in timeline.get('events', []):
        print(f" • {event['modified']:<20} | {event['layer']:<12} | {event['file']}")
    
    print(">>> END_LAYER\n")
    sys.stdout.flush()

    # 6. AUTO-REPORT GENERATION
    report_path = generate_report(
        all_detections, 
        fci_score, 
        determination, 
        correlation['summary'], 
        timeline # Now this variable is defined!
    )
    
    print(">>> LAYER: DASHBOARD")
    print(f"\n[*] Formal Evidence Report generated: {report_path}")
    print("[!] INVESTIGATION COMPLETE")
    print(">>> END_LAYER")
    sys.stdout.flush()

if __name__ == "__main__":
    main()
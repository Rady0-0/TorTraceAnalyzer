import sys
import os

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
    # 1. EVIDENCE INGESTION
    # Standard input handling for individual files or entire evidence directories.
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

    print("="*65)
    print(f"{'TOR TRACE ANALYZER - MULTI-LAYER FORENSIC SUITE':^65}")
    print("="*65 + "\n")

    all_detections = []
    layer_hits = {"memory": False, "system": False, "network": False, "application": False}

    # 2. MULTI-HIT ANALYSIS LOOP
    # Iterates through every file and every layer to ensure zero-loss detection.
    for f_path in evidence_files:
        parsed_data = parse_forensic_file(f_path)
        
        layers = [
            ("MEMORY", check_memory), ("SYSTEM", check_system),
            ("NETWORK", check_network), ("APPLICATION", check_application)
        ]

        for name, func in layers:
            # Each function now returns a LIST of all artifacts found
            results = func(parsed_data)
            
            for result in results:
                if result.get("status") == "Detected":
                    all_detections.append(result)
                    layer_hits[name.lower()] = True
                    
                    # SYSTEM ROUTING TAGS (GUI COMPATIBLE)
                    print(f">>> LAYER: {name.upper()}")
                    print(f"    STATUS   : DETECTED")
                    print(f"    ARTIFACT : {result['file_name']}")
                    print(f"    PATH     : {result['file_path']}")
                    print(f"    OCCURRED : {result['disk_timestamps'].get('modified', 'N/A')}")
                    print(f"    NOTE     : {result['message']}")
                    print(f">>> END_LAYER\n")

    # 3. BEHAVIORAL PATTERN CORRELATION
    # Identifies complex investigative stories like Exfiltration or Log Wiping.
    correlation = correlate_artifacts(layer_hits, all_detections)
    print(">>> LAYER: DASHBOARD")
    print(f"\n[FORENSIC CORRELATION SUMMARY]:\n{correlation['summary']}\n")
    print(">>> END_LAYER")

    # 4. CHRONOLOGICAL TIMELINE RECONSTRUCTION
    # Reconstructs activity based on internal metadata extracted from the reports.
    timeline = build_timeline(all_detections)
    print(">>> LAYER: TIMELINE")
    print(f"{'TIMESTAMP':<22} | {'LAYER':<12} | {'ARTIFACT'}")
    print("-" * 65)
    for event in timeline["events"]:
        print(f" • {event['time']:<20} | {event['layer']:<12} | {event['file']}")
    print(">>> END_LAYER\n")

    # 5. CONFIDENCE SCORING & FINAL OUTPUT
    # Mathematically weights findings to determine the likelihood of Tor activity.
    fci_score, determination = calculate_fci(layer_hits)
    print(f"\nFORENSIC CONFIDENCE INDEX (FCI): {fci_score:.1f}%")
    print(f"INVESTIGATIVE DETERMINATION: {determination}")

    # Generate the professional evidence report (PDF/TXT)
    report_path = generate_report(all_detections, fci_score, determination, layer_hits)
    print(f"\n[*] Formal Evidence Report generated: {report_path}")
    print("[!] INVESTIGATION COMPLETE")

if __name__ == "__main__":
    main()
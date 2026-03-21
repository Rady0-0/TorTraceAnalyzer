import datetime
import os

def generate_report(all_detections, fci_score, determination, layer_results):
    """
    Generates a professional forensic report saved directly to the user's Desktop.
    Resolves [Errno 13] Permission Denied by using a guaranteed writeable path.
    """
    
    # --- 1. RESOLVE PERMISSION-SAFE PATH ---
    # This finds 'C:\Users\<User>\Desktop' automatically
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    
    timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"TorTrace_Forensic_Report_{timestamp_str}.txt"
    
    # Create the full absolute path
    full_report_path = os.path.join(desktop_path, report_filename)
    
    try:
        with open(full_report_path, "w", encoding="utf-8") as r:
            # --- REPORT HEADER ---
            r.write("=" * 90 + "\n")
            r.write(f"{'TORTRACE ANALYZER - FORENSIC EXAMINATION REPORT':^90}\n")
            r.write(f"{'Generated on: ' + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'):^90}\n")
            r.write("=" * 90 + "\n\n")

            # --- 1. EXECUTIVE SUMMARY ---
            r.write("1. EXECUTIVE SUMMARY\n")
            r.write("-" * 20 + "\n")
            r.write(f"Forensic Confidence Index (FCI): {fci_score:.1f}%\n")
            r.write(f"Investigative Determination:    {determination}\n")
            r.write(f"Total Artifacts Identified:      {len(all_detections)}\n\n")

            # --- 2. LAYER DETECTION SUMMARY ---
            r.write("2. LAYER DETECTION SUMMARY\n")
            r.write("-" * 28 + "\n")
            layers = ["Memory", "System", "Network", "Application"]
            for l in layers:
                status = "DETECTED" if layer_results.get(l.lower()) else "NOT DETECTED"
                r.write(f"[*] {l:<12} : {status}\n")
            r.write("\n")

            # --- 3. INVESTIGATIVE FINDINGS & DETAILED LOGS ---
            r.write("3. INVESTIGATIVE FINDINGS & DETAILED LOGS\n")
            r.write("-" * 42 + "\n")
            for i, d in enumerate(all_detections, 1):
                r.write(f"Finding #{i} [{d['layer']} Layer]:\n")
                r.write(f"    - Name:     {d['file_name']}\n")
                r.write(f"    - Path:     {d['file_path']}\n")
                r.write(f"    - Note:     {d['message']}\n")
                
                ts = d['disk_timestamps']
                r.write(f"    - Modified: {ts.get('modified', 'N/A')}\n")
                r.write(f"    - Accessed: {ts.get('accessed', 'N/A')}\n")
                r.write(f"    - Created:  {ts.get('created', 'N/A')}\n")
                r.write("-" * 45 + "\n")
            r.write("\n")

            # --- 4. FORENSIC TIMELINE (MACB EVENTS) ---
            r.write("4. FORENSIC TIMELINE (CHRONOLOGICAL)\n")
            r.write("-" * 37 + "\n")
            r.write(f"{'TIMESTAMP (MODIFIED)':<22} | {'LAYER':<12} | {'ARTIFACT NAME'}\n")
            r.write("-" * 90 + "\n")
            
            # Chronological sort based on disk modification time
            sorted_timeline = sorted(all_detections, key=lambda x: x['disk_timestamps'].get('modified', ''))
            for entry in sorted_timeline:
                m_time = entry['disk_timestamps'].get('modified', 'N/A')
                r.write(f"{m_time:<22} | {entry['layer']:<12} | {entry['file_name']}\n")

        # Return the full path so the GUI can notify the user exactly where it is
        return full_report_path

    except PermissionError:
        # Emergency fallback if even the Desktop is blocked (rare)
        return "Permission Denied: Could not save report to Desktop."
    except Exception as e:
        return f"Error: {str(e)}"
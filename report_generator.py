import datetime
import os
import json
import pandas as pd

def generate_report(all_detections, fci_score, determination, correlation_summary, timeline_data):
    """
    AUTO-REPORT: The professional TXT log generated on the desktop.
    """
    report_dir = _get_smart_path()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    full_path = os.path.join(report_dir, f"TorTrace_Log_{timestamp}.txt")
    
    try:
        with open(full_path, "w", encoding="utf-8") as r:
            r.write("=" * 95 + "\n")
            r.write(f"{'TORTRACE ANALYZER - MULTI-LAYER FORENSIC CASE LOG':^95}\n")
            r.write(f"{'Generated: ' + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'):^95}\n")
            r.write("=" * 95 + "\n\n")

            r.write(f"1. EXECUTIVE DETERMINATION\n{'-'*30}\n")
            r.write(f"CONFIDENCE INDEX : {fci_score:.1f}%\n")
            r.write(f"DETERMINATION    : {determination}\n")
            r.write(f"BEHAVIORAL LOGIC : {correlation_summary}\n\n")

            r.write(f"2. MASTER EVENT TIMELINE (MACB)\n{'-'*30}\n")
            r.write(f"{'TIMESTAMP (MODIFIED)':<22} | {'LAYER':<12} | {'ARTIFACT':<25} | {'ANOMALY'}\n")
            r.write("-" * 95 + "\n")
            for event in timeline_data.get("events", []):
                r.write(f"{event['modified']:<22} | {event['layer']:<12} | {event['file']:<25} | {event['anomaly']}\n")
            
            r.write(f"\n3. DETAILED EVIDENCE FINDINGS\n{'-'*30}\n")
            for i, d in enumerate(all_detections, 1):
                ts = d.get('disk_timestamps', {})
                r.write(f"FINDING #{i} [{d.get('layer')}]\n")
                r.write(f"    - Artifact : {d.get('file_name')}\n")
                r.write(f"    - Proof    : {d.get('evidence_match')}\n")
                r.write(f"    - Path     : {d.get('file_path')}\n")
                r.write(f"    - Analysis : {d.get('message')}\n")
                r.write("-" * 50 + "\n")
                
        return full_path
    except Exception as e:
        return f"Error: {str(e)}"

def export_custom_report(all_detections, fci_score, determination, correlation_summary, timeline_data, format_type, target_path):
    """
    MANUAL EXPORT: Triggered by GUI. Now includes Timeline and Behavioral Logic.
    """
    try:
        format_type = format_type.upper()
        
        # 1. Prepare Evidence Data
        flat_data = []
        for d in all_detections:
            ts = d.get('disk_timestamps', {})
            flat_data.append({
                "Layer": d.get("layer"),
                "Artifact": d.get("file_name"),
                "Modified": ts.get('modified'),
                "Evidence Proof": d.get("evidence_match"),
                "Forensic Note": d.get("message"),
                "Path": d.get("file_path")
            })
        df_evidence = pd.DataFrame(flat_data)
        
        # 2. Prepare Timeline Data
        df_timeline = pd.DataFrame(timeline_data.get("events", []))

        # 3. Format-Specific Export
        if format_type == "EXCEL":
            # Multi-sheet Excel is the gold standard for final year projects
            with pd.ExcelWriter(target_path, engine='openpyxl') as writer:
                df_evidence.to_excel(writer, sheet_name='Evidence Findings', index=False)
                df_timeline.to_excel(writer, sheet_name='MACB Timeline', index=False)
                
                summary_df = pd.DataFrame({
                    "Forensic Metric": ["FCI Score", "Final Determination", "Correlated Pattern"],
                    "Value": [f"{fci_score}%", determination, correlation_summary]
                })
                summary_df.to_excel(writer, sheet_name='Case Summary', index=False)

        elif format_type == "CSV":
            # Combined CSV for simple data viewing
            df_evidence.to_csv(target_path, index=False)
            
        elif format_type == "JSON":
            with open(target_path, "w") as f:
                json.dump({
                    "case_summary": {"fci": fci_score, "determination": determination, "behavior": correlation_summary},
                    "timeline": timeline_data.get("events", []),
                    "evidence": flat_data
                }, f, indent=4)
        
        return True
    except Exception as e:
        print(f"Export Error: {e}")
        return False

def _get_smart_path():
    path = os.path.join(os.path.expanduser("~"), "Desktop")
    if not os.path.exists(path):
        path = os.path.join(os.path.expanduser("~"), "OneDrive", "Desktop")
    return path if os.path.exists(path) else os.getcwd()
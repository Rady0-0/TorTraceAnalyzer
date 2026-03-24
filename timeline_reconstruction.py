from datetime import datetime

def build_timeline(all_detections):
    """
    Step 7: MACB Timeline Reconstruction.
    Synchronizes timestamps across all layers to create a master history.
    """
    
    # 1. SORTING LOGIC
    # We sort by 'Modified' time. 
    # Fallback to '1970' ensures empty dates don't crash the sort.
    def sort_key(x):
        ts = x['disk_timestamps'].get('modified', '1970-01-01 00:00:00')
        # If it's 'Live Capture' (Memory) or 'N/A', we treat it as an older event
        if not any(char.isdigit() for char in ts):
            return "1970-01-01 00:00:00"
        return ts

    sorted_events = sorted(all_detections, key=sort_key)
    
    timeline_data = {
        "events": [],
        "summary": f"Reconstructed {len(sorted_events)} forensic events across multiple layers."
    }

    # 2. CHRONOLOGICAL MAPPING
    for det in sorted_events:
        ts = det.get('disk_timestamps', {})
        m = ts.get('modified', 'N/A')
        c = ts.get('created', 'N/A')
        a = ts.get('accessed', 'N/A')

        # --- FORENSIC DEPTH: Timestomping Detection ---
        # Requirement: Prove investigative anomalies.
        # Logic: If a file's 'Birth/Created' date is LATER than its 'Modified' date, 
        # it is a major NTFS anomaly often caused by timestomping tools.
        anomaly_note = ""
        try:
            if m != "N/A" and c != "N/A" and any(char.isdigit() for char in m + c):
                # Standardize for comparison
                m_dt = datetime.strptime(m, '%Y-%m-%d %H:%M:%S')
                c_dt = datetime.strptime(c, '%Y-%m-%d %H:%M:%S')
                
                if c_dt > m_dt:
                    anomaly_note = "[!] ANOMALY: Possible Timestomping (Created > Modified)"
        except:
            pass # Handle non-standard formats gracefully

        timeline_data["events"].append({
            "modified": m,
            "created": c,
            "accessed": a,
            "layer": det['layer'],
            "file": det['file_name'],
            "anomaly": anomaly_note
        })
        
    return timeline_data
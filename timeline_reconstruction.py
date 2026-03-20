def build_timeline(all_detections):
    """
    Takes all identified artifacts and reconstructs a chronological 
    history of the suspect's activity.
    """
    # Sort detections by the 'Modified' timestamp
    # Requirements 1: Focus on Modified time as the primary anchor
    sorted_events = sorted(
        all_detections, 
        key=lambda x: x['disk_timestamps'].get('modified', ''), 
        reverse=True # Newest events first
    )
    
    timeline_data = {
        "events": [],
        "summary": f"Reconstructed {len(sorted_events)} forensic events."
    }

    for det in sorted_events:
        timeline_data["events"].append({
            "time": det['disk_timestamps'].get('modified', 'N/A'),
            "layer": det['layer'],
            "type": "EXECUTION" if det['layer'] == "Memory" else "TRACE",
            "file": det['file_name']
        })
        
    return timeline_data
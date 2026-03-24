import os
import datetime
import json
import re
import pandas as pd
from docx import Document

def parse_forensic_file(filepath):
    """
    Standardizing forensic report ingestion. 
    SPEED FIX: Replaced BeautifulSoup with Fast-Regex for HTML.
    """
    ext = os.path.splitext(filepath)[1].lower()
    abs_path = os.path.abspath(filepath)
    stats = os.stat(filepath)
    
    # Requirement 1: Capture the MACB metadata of the report file itself.
    timestamps = {
        "modified": datetime.datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
        "accessed": datetime.datetime.fromtimestamp(stats.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
        "created": datetime.datetime.fromtimestamp(stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
    }

    content = ""
    try:
        # 1. FAST HTML PROCESSING (BeautifulSoup is too slow for large forensic files)
        if ext in [".html", ".htm"]:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                raw_html = f.read()
                # Use regex to strip tags; 100x faster than BeautifulSoup
                content = re.sub(r'<[^>]*>', ' ', raw_html) 
        
        # 2. STANDARD TEXT/LOG PROCESSING
        elif ext in [".txt", ".log", ".csv"]:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f: 
                content = f.read()
        
        # 3. OTHER FORMATS
        elif ext == ".json":
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = json.dumps(json.load(f), indent=2)
        elif ext in [".xlsx", ".xls"]:
            content = pd.read_excel(filepath).to_string()        
        elif ext == ".docx":
            content = "\n".join([p.text for p in Document(filepath).paragraphs])
            
    except Exception as e:
        content = f"Parsing Error: {str(e)}"

    # Requirement 3: Evidence Classification (The Brain)
    content_lower = content.lower()
    
    # --- SIGNATURE SETS ---
    disk_signatures = ["/img_", "/vol_", "partition", "standard information", "attribute id", "autopsy", "e01"]
    memory_headers = ["volatility foundation", "pslist", "netscan", "dlllist", "malfind"]
    network_signatures = ["source ip", "destination ip", "protocol", "packet length", "tshark", "pcap"]

    # --- CLASSIFICATION ENGINE (Priority: DISK -> MEMORY -> NETWORK) ---
    if any(sig in content_lower for sig in disk_signatures):
        evidence_type = "DISK"
    elif any(header in content_lower for header in memory_headers) or ext in [".raw", ".mem"]:
        evidence_type = "MEMORY"
    elif any(sig in content_lower for sig in network_signatures) or "network" in filepath.lower():
        evidence_type = "NETWORK"
    else:
        evidence_type = "DISK"

    return {
        "content": content_lower,
        "path": abs_path,
        "filename": os.path.basename(filepath),
        "timestamps": timestamps,
        "evidence_type": evidence_type 
    }
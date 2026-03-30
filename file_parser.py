import os
import datetime
import json
import re
import pandas as pd
from docx import Document


# ============================================
# 🔥 SAFE BINARY STRING EXTRACTOR
# ============================================
def extract_strings_from_binary(filepath, min_length=4, max_size_mb=50):
    try:
        file_size = os.path.getsize(filepath) / (1024 * 1024)

        # ⚠️ Prevent huge file freeze
        if file_size > max_size_mb:
            return "[SKIPPED LARGE BINARY FILE]"

        with open(filepath, "rb") as f:
            data = f.read()

        strings = re.findall(rb"[ -~]{%d,}" % min_length, data)
        return b"\n".join(strings).decode(errors="ignore")

    except Exception as e:
        return f"Binary parsing error: {str(e)}"


# ============================================
# MAIN PARSER
# ============================================
def parse_forensic_file(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    abs_path = os.path.abspath(filepath)
    stats = os.stat(filepath)

    timestamps = {
        "modified": datetime.datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
        "accessed": datetime.datetime.fromtimestamp(stats.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
        "created": datetime.datetime.fromtimestamp(stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
    }

    content = ""
    evidence_type = "DISK"

    try:
        # ============================================
        # 1. HTML
        # ============================================
        if ext in [".html", ".htm"]:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                raw_html = f.read()
                content = re.sub(r'<[^>]*>', ' ', raw_html)

        # ============================================
        # 2. TEXT FILES
        # ============================================
        elif ext in [".txt", ".log", ".csv"]:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

        # ============================================
        # 3. STRUCTURED FILES
        # ============================================
        elif ext == ".json":
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = json.dumps(json.load(f), indent=2)

        elif ext in [".xlsx", ".xls"]:
            content = pd.read_excel(filepath).to_string()

        elif ext == ".docx":
            content = "\n".join([p.text for p in Document(filepath).paragraphs])

        # ============================================
        # 🔥 4. MEMORY / RAW BINARIES (SAFE)
        # ============================================
        elif ext in [".raw", ".mem", ".dmp", ".bin"]:
            content = extract_strings_from_binary(filepath)
            evidence_type = "MEMORY"

        # ============================================
        # 🔥 5. E01 (DO NOT PARSE DIRECTLY)
        # ============================================
        elif ext == ".e01":
            content = "[E01 IMAGE DETECTED - USE AUTOPSY FOR ANALYSIS]"
            evidence_type = "DISK"

        # ============================================
        # 🔥 6. PCAP (handled separately)
        # ============================================
        elif ext in [".pcap", ".pcapng"]:
            content = ""
            evidence_type = "PCAP"

        else:
            content = extract_strings_from_binary(filepath)

    except Exception as e:
        content = f"Parsing Error: {str(e)}"

    content_lower = content.lower()

    # ============================================
    # INTELLIGENT CLASSIFICATION
    # ============================================
    disk_signatures = ["/img_", "/vol_", "partition", "autopsy", "e01"]
    memory_headers = ["volatility foundation", "pslist", "netscan"]
    network_signatures = ["source ip", "destination ip", "protocol", "packet"]

    if evidence_type == "PCAP":
        pass

    elif evidence_type == "MEMORY":
        pass

    elif ext == ".e01":
        pass

    elif any(sig in content_lower for sig in disk_signatures):
        evidence_type = "DISK"

    elif any(header in content_lower for header in memory_headers):
        evidence_type = "MEMORY"

    elif any(sig in content_lower for sig in network_signatures):
        evidence_type = "NETWORK"

    return {
        "content": content_lower,
        "path": abs_path,
        "filename": os.path.basename(filepath),
        "timestamps": timestamps,
        "evidence_type": evidence_type
    }

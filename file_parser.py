import os
import datetime
import json
import re
import pandas as pd
from docx import Document


MAX_TEXT_BYTES = 5 * 1024 * 1024
MAX_TEXT_CHARS = 1_500_000
MAX_EXCEL_ROWS = 350
MAX_DOCX_PARAGRAPHS = 600


def read_text_safely(filepath, strip_html=False):
    size_bytes = os.path.getsize(filepath)
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read(min(size_bytes, MAX_TEXT_BYTES))

    if strip_html:
        content = re.sub(r"<[^>]*>", " ", content)

    if size_bytes > MAX_TEXT_BYTES:
        content += "\n[TRUNCATED LARGE TEXT FILE]"

    return content[:MAX_TEXT_CHARS]


def read_json_safely(filepath):
    size_bytes = os.path.getsize(filepath)
    if size_bytes > MAX_TEXT_BYTES:
        return read_text_safely(filepath)

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return json.dumps(json.load(f), indent=2)[:MAX_TEXT_CHARS]


def read_excel_safely(filepath):
    return pd.read_excel(filepath, nrows=MAX_EXCEL_ROWS).to_string()[:MAX_TEXT_CHARS]


def read_docx_safely(filepath):
    paragraphs = [p.text for p in Document(filepath).paragraphs[:MAX_DOCX_PARAGRAPHS]]
    content = "\n".join(paragraphs)
    if len(paragraphs) >= MAX_DOCX_PARAGRAPHS:
        content += "\n[TRUNCATED LARGE DOCX FILE]"
    return content[:MAX_TEXT_CHARS]


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
            content = read_text_safely(filepath, strip_html=True)

        # ============================================
        # 2. TEXT FILES
        # ============================================
        elif ext in [".txt", ".log", ".csv"]:
            content = read_text_safely(filepath)

        # ============================================
        # 3. STRUCTURED FILES
        # ============================================
        elif ext == ".json":
            content = read_json_safely(filepath)

        elif ext in [".xlsx", ".xls"]:
            content = read_excel_safely(filepath)

        elif ext == ".docx":
            content = read_docx_safely(filepath)

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

import datetime
import json
import os
import re

import pandas as pd
from docx import Document


MAX_TEXT_BYTES = 5 * 1024 * 1024
MAX_TEXT_CHARS = 1_500_000
MAX_EXCEL_ROWS = 350
MAX_DOCX_PARAGRAPHS = 600
LARGE_TEXT_HEADER_LINES = 60
LARGE_TEXT_MAX_MATCHED_LINES = 1200
MAX_BINARY_SCAN_BYTES = 512 * 1024 * 1024
BINARY_CHUNK_SIZE = 2 * 1024 * 1024
BINARY_MAX_MATCHED_STRINGS = 12000
LARGE_TEXT_RELEVANT_KEYWORDS = [
    "tor browser.lnk",
    "tor browser",
    "torbrowser",
    "tor.exe",
    "firefox.exe",
    "places.sqlite",
    "cookies.sqlite",
    "torrc",
    "noscript",
    "usbstor",
    ".onion",
    "wireguard",
    "openvpn",
    "port 9050",
    "port 9150",
    "port 9001",
    "port 9030",
    ":9050",
    ":9150",
    ":9001",
    ":9030",
]
MEMORY_RELEVANT_KEYWORDS = [
    "tor",
    "tor.exe",
    "torrc",
    "firefox.exe",
    ".onion",
    "onion",
    "socksport",
    "controlport",
    "obfs4",
    "bridge",
    "volatility foundation",
    "pslist",
    "netscan",
]


def extract_relevant_lines_from_large_text(filepath, strip_html=False):
    header_lines = []
    relevant_lines = []
    seen_lines = set()

    with open(filepath, "r", encoding="utf-8", errors="ignore") as file_obj:
        for line_number, raw_line in enumerate(file_obj):
            line = raw_line.rstrip("\n")

            if strip_html:
                line = re.sub(r"<[^>]*>", " ", line)

            if line_number < LARGE_TEXT_HEADER_LINES:
                header_lines.append(line)

            line_lower = line.lower()
            if any(keyword in line_lower for keyword in LARGE_TEXT_RELEVANT_KEYWORDS):
                normalized = line.strip()
                if normalized and normalized not in seen_lines:
                    seen_lines.add(normalized)
                    relevant_lines.append(normalized)
                    if len(relevant_lines) >= LARGE_TEXT_MAX_MATCHED_LINES:
                        break

    combined = header_lines + [""] + relevant_lines
    combined.append("[TRUNCATED LARGE TEXT FILE - RELEVANT LINES EXTRACTED]")
    return "\n".join(combined)[:MAX_TEXT_CHARS]


def read_text_safely(filepath, strip_html=False):
    size_bytes = os.path.getsize(filepath)
    if size_bytes > MAX_TEXT_BYTES:
        return extract_relevant_lines_from_large_text(filepath, strip_html=strip_html)

    with open(filepath, "r", encoding="utf-8", errors="ignore") as file_obj:
        content = file_obj.read(size_bytes)

    if strip_html:
        content = re.sub(r"<[^>]*>", " ", content)

    return content[:MAX_TEXT_CHARS]


def read_json_safely(filepath):
    size_bytes = os.path.getsize(filepath)
    if size_bytes > MAX_TEXT_BYTES:
        return read_text_safely(filepath)

    with open(filepath, "r", encoding="utf-8", errors="ignore") as file_obj:
        return json.dumps(json.load(file_obj), indent=2)[:MAX_TEXT_CHARS]


def read_excel_safely(filepath):
    return pd.read_excel(filepath, nrows=MAX_EXCEL_ROWS).to_string()[:MAX_TEXT_CHARS]


def read_docx_safely(filepath):
    paragraphs = [paragraph.text for paragraph in Document(filepath).paragraphs[:MAX_DOCX_PARAGRAPHS]]
    content = "\n".join(paragraphs)
    if len(paragraphs) >= MAX_DOCX_PARAGRAPHS:
        content += "\n[TRUNCATED LARGE DOCX FILE]"
    return content[:MAX_TEXT_CHARS]


def _binary_string_is_relevant(text):
    text_lower = text.lower()
    return any(keyword in text_lower for keyword in MEMORY_RELEVANT_KEYWORDS)


# Safe binary string extraction for memory-like evidence files.
def extract_strings_from_binary(filepath, min_length=4):
    try:
        file_size = os.path.getsize(filepath)
        bytes_to_scan = min(file_size, MAX_BINARY_SCAN_BYTES)
        matched_strings = []
        total_chars = 0
        carry = b""
        pattern = re.compile(rb"[ -~]{%d,}" % min_length)

        with open(filepath, "rb") as file_obj:
            scanned = 0
            while scanned < bytes_to_scan and len(matched_strings) < BINARY_MAX_MATCHED_STRINGS:
                chunk = file_obj.read(min(BINARY_CHUNK_SIZE, bytes_to_scan - scanned))
                if not chunk:
                    break

                scanned += len(chunk)
                data = carry + chunk
                carry = b""
                matches = list(pattern.finditer(data))

                for index, match in enumerate(matches):
                    text_bytes = match.group(0)
                    is_tail_match = index == len(matches) - 1 and match.end() == len(data) and scanned < bytes_to_scan
                    if is_tail_match:
                        carry = text_bytes[-512:]
                        continue

                    text = text_bytes.decode(errors="ignore").strip()
                    if not text or not _binary_string_is_relevant(text):
                        continue

                    if len(text) > 500:
                        text = text[:500] + "..."

                    projected_size = total_chars + len(text) + 1
                    if projected_size > MAX_TEXT_CHARS:
                        break

                    matched_strings.append(text)
                    total_chars = projected_size

                if total_chars >= MAX_TEXT_CHARS:
                    break

        if not matched_strings:
            matched_strings.append("[BINARY SCAN COMPLETED - NO TOR-RELEVANT STRINGS FOUND]")

        if file_size > bytes_to_scan:
            matched_strings.append("[TRUNCATED LARGE BINARY FILE - PARTIAL SCAN COMPLETED]")

        return "\n".join(matched_strings)[:MAX_TEXT_CHARS]

    except Exception as exc:
        return f"Binary parsing error: {exc}"


# Main parser.
def parse_forensic_file(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    abs_path = os.path.abspath(filepath)
    stats = os.stat(filepath)

    timestamps = {
        "modified": datetime.datetime.fromtimestamp(stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        "accessed": datetime.datetime.fromtimestamp(stats.st_atime).strftime("%Y-%m-%d %H:%M:%S"),
        "created": datetime.datetime.fromtimestamp(stats.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
    }

    content = ""
    evidence_type = "DISK"

    try:
        if ext in [".html", ".htm"]:
            content = read_text_safely(filepath, strip_html=True)
        elif ext in [".txt", ".log", ".csv"]:
            content = read_text_safely(filepath)
        elif ext == ".json":
            content = read_json_safely(filepath)
        elif ext in [".xlsx", ".xls"]:
            content = read_excel_safely(filepath)
        elif ext == ".docx":
            content = read_docx_safely(filepath)
        elif ext in [".raw", ".mem", ".dmp", ".bin"]:
            content = extract_strings_from_binary(filepath)
            evidence_type = "MEMORY"
        elif ext == ".e01":
            content = "[E01 IMAGE DETECTED - USE AUTOPSY FOR ANALYSIS]"
            evidence_type = "DISK"
        elif ext in [".pcap", ".pcapng"]:
            content = ""
            evidence_type = "PCAP"
        else:
            content = extract_strings_from_binary(filepath)
    except Exception as exc:
        content = f"Parsing Error: {exc}"

    content_lower = content.lower()

    disk_signatures = ["/img_", "/vol_", "partition", "autopsy", "e01"]
    disk_artifact_signatures = [
        "prefetch",
        "places.sqlite",
        "cookies.sqlite",
        "torrc",
        "usbstor",
        "\\windows\\",
        "\\users\\",
        "/users/",
    ]
    memory_headers = ["volatility foundation", "pslist", "netscan"]
    network_signatures = ["source ip", "destination ip", "protocol", "packet"]

    if evidence_type == "PCAP":
        pass
    elif evidence_type == "MEMORY":
        pass
    elif ext == ".e01":
        pass
    elif any(signature in content_lower for signature in disk_signatures):
        evidence_type = "DISK"
    elif any(signature in content_lower for signature in disk_artifact_signatures):
        evidence_type = "DISK"
    elif any(header in content_lower for header in memory_headers):
        evidence_type = "MEMORY"
    elif any(signature in content_lower for signature in network_signatures):
        evidence_type = "NETWORK"

    return {
        "content": content_lower,
        "path": abs_path,
        "filename": os.path.basename(filepath),
        "timestamps": timestamps,
        "evidence_type": evidence_type,
    }

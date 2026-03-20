import os
import csv
import json
import datetime
import re
from docx import Document # Requires: pip install python-docx
from bs4 import BeautifulSoup # Requires: pip install beautifulsoup4
import pandas as pd # Requires: pip install pandas openpyxl

def parse_forensic_file(filepath):
    """
    Unified parser for multiple forensic formats.
    Returns a dictionary with Content, Paths, and MACB Timestamps.
    """
    ext = os.path.splitext(filepath)[1].lower()
    abs_path = os.path.abspath(filepath)
    stats = os.stat(filepath)
    
    # MACB Extraction
    timestamps = {
        "modified": datetime.datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
        "accessed": datetime.datetime.fromtimestamp(stats.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
        "created": datetime.datetime.fromtimestamp(stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
        "birth": "N/A" # OS dependent, usually handled by 'created' on Windows
    }

    content = ""
    try:
        if ext in [".txt", ".log", ".csv"]:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
        elif ext == ".xlsx":
            # Read all sheets and combine into one text block
            df = pd.read_excel(filepath)
            content = df.to_string()        
        elif ext == ".json":
            with open(filepath, 'r') as f:
                content = json.dumps(json.load(f))
        elif ext in [".html", ".htm"]:
            with open(filepath, 'r', errors='ignore') as f:
                content = BeautifulSoup(f.read(), "html.parser").get_text()
        elif ext == ".docx":
            doc = Document(filepath)
            content = "\n".join([p.text for p in doc.paragraphs])
    except Exception as e:
        content = f"Error parsing {ext}: {str(e)}"

    return {
        "content": content.lower(),
        "path": abs_path,
        "filename": os.path.basename(filepath),
        "timestamps": timestamps
    }
import os
import csv
import json


def read_file_content(file):

    extension = os.path.splitext(file)[1].lower()

    try:

        if extension in [".txt", ".log"]:
            with open(file, "r", errors="ignore") as f:
                return f.read().lower()

        elif extension == ".csv":
            data = ""
            with open(file, newline='', errors="ignore") as f:
                reader = csv.reader(f)
                for row in reader:
                    data += " ".join(row).lower()
            return data

        elif extension == ".json":
            with open(file, "r", errors="ignore") as f:
                return json.dumps(json.load(f)).lower()

        else:
            return ""

    except:
        return ""


def check_system(file):

    data = read_file_content(file)

    indicators = [
        "tor.exe.pf",
        "firefox.exe.pf",
        "prefetch",
        "tor browser",
        "last run time"
    ]

    if any(indicator in data for indicator in indicators):

        return "[System Layer] Tor execution artifacts detected"

    else:

        return "[System Layer] No Tor execution artifacts detected"
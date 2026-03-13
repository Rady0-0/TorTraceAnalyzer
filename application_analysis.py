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


def check_application(file):

    data = read_file_content(file)

    application_indicators = [
        "tor browser",
        "places.sqlite",
        "cookies.sqlite",
        "webappsstore.sqlite",
        "profile.default",
        "torprofile"
    ]

    detected = []

    for indicator in application_indicators:
        if indicator in data:
            detected.append(indicator)

    if detected:

        return "[Application Layer] Tor browser artifacts detected: " + ", ".join(detected)

    else:

        return "[Application Layer] No Tor browser artifacts detected"
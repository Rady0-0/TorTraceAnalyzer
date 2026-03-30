import json
import os

from app_paths import get_case_file_path


CASE_FILE = get_case_file_path()

def save_case(case_data):
    cases = load_cases()
    cases.append(case_data)

    os.makedirs(os.path.dirname(CASE_FILE), exist_ok=True)
    with open(CASE_FILE, "w", encoding="utf-8") as f:
        json.dump(cases, f, indent=4)


def load_cases():
    if not os.path.exists(CASE_FILE):
        return []

    try:
        with open(CASE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

    return data if isinstance(data, list) else []


def get_case_names():
    return [
        c.get("case_name") or c.get("case_number") or "Unknown"
        for c in load_cases()
    ]

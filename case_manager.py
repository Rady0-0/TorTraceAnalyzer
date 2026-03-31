import json
import os

from app_paths import get_case_file_path


CASE_FILE = get_case_file_path()


def _case_identity(case_data):
    case_id = (case_data or {}).get("case_id", "").strip()
    case_name = (case_data or {}).get("case_name", "").strip()
    return case_id, case_name


def save_case(case_data):
    cases = load_cases()
    case_id, case_name = _case_identity(case_data)
    updated = False

    for index, existing_case in enumerate(cases):
        existing_id, existing_name = _case_identity(existing_case)
        if case_id and existing_id and case_id == existing_id:
            cases[index] = case_data
            updated = True
            break
        if not case_id and case_name and existing_name == case_name:
            cases[index] = case_data
            updated = True
            break

    if not updated:
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


def get_case_by_name(case_name):
    for case in load_cases():
        stored_name = case.get("case_name") or case.get("case_number")
        if stored_name == case_name:
            return case
    return None

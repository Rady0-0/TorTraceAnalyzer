import re


def extract_internal_metadata(content, default_ts, artifact_name):
    time_pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    path_pattern = r"([a-zA-Z]:\\[\\\w \.\-\(\)]+|/[\w \.\-\(\)/]+)"
    artifact_lower = artifact_name.lower()

    for line in content.splitlines():
        if artifact_lower not in line.lower():
            continue

        times = re.findall(time_pattern, line)
        paths = re.findall(path_pattern, line)
        raw_path = "Path not found"
        for path in paths:
            if artifact_lower in path.lower():
                raw_path = path
                break
        if raw_path == "Path not found" and paths:
            raw_path = paths[0]
        return {
            "time": times[0] if times else default_ts.get("modified", "N/A"),
            "path": raw_path,
        }

    idx = content.find(artifact_lower)
    if idx == -1:
        return {"time": "N/A", "path": "Path not found"}

    window_start = max(0, idx - 500)
    window = content[window_start: min(len(content), idx + 500)]
    times = list(re.finditer(time_pattern, window))
    paths = re.findall(path_pattern, window)

    raw_path = "Path not found"
    for path in paths:
        if artifact_lower in path.lower():
            raw_path = path
            break
    if raw_path == "Path not found" and paths:
        raw_path = paths[0]

    chosen_time = default_ts.get("modified", "N/A")
    relative_idx = idx - window_start
    preceding_times = [match.group(1) for match in times if match.start() <= relative_idx]
    if preceding_times:
        chosen_time = preceding_times[-1]
    elif times:
        chosen_time = times[0].group(1)

    return {
        "time": chosen_time,
        "path": raw_path,
    }


def check_application(file_data):
    content = file_data.get("content", "").lower()
    ts_metadata = file_data.get("timestamps", {})
    results = []

    app_indicators = {
        "places.sqlite": "History Database: Contains Tor browsing activity.",
        "cookies.sqlite": "Session Data: Evidence of Tor browsing sessions.",
        "noscript": "Security Policy: Indicates Tor Browser hardened mode.",
        "torrc": "Core Config: Defines Tor network behavior and routing.",
    }

    tor_path_hints = [
        "tor",
        "tor browser",
        "onion",
        "browser\\torbrowser",
        "browser/torbrowser",
        "profile.default",
    ]
    excluded_paths = ["windows", "microsoft", "onesettings"]

    for artifact, reason in app_indicators.items():
        if artifact not in content:
            continue

        pattern = rf"\b{re.escape(artifact)}\b"
        if not re.search(pattern, content):
            continue

        ext = extract_internal_metadata(content, ts_metadata, artifact)
        idx = content.find(artifact)
        window = content[max(0, idx - 500): min(len(content), idx + 500)] if idx != -1 else ""

        path_lower = ext["path"].lower()
        context_lower = window.lower()

        if any(excl in path_lower for excl in excluded_paths):
            continue

        if not any(hint in path_lower or hint in context_lower for hint in tor_path_hints):
            continue

        match = re.search(rf"\b[\w\.-]*{artifact}[\w\.-]*\b", content)
        evidence_match = match.group(0).upper() if match else artifact.upper()

        results.append(
            {
                "layer": "Application",
                "status": "Detected",
                "file_name": artifact.upper(),
                "file_path": ext["path"],
                "message": reason,
                "evidence_match": f"Application Anchor: {evidence_match}",
                "disk_timestamps": {
                    "modified": ext["time"],
                    "created": ts_metadata.get("created", "N/A"),
                    "accessed": ts_metadata.get("accessed", "N/A"),
                },
            }
        )

    return results

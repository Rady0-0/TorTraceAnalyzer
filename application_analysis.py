import re

def extract_internal_metadata(content, default_ts, artifact_name):
    time_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    times = re.findall(time_pattern, content)
    path_pattern = r'([a-zA-Z]:\\[\\\w\s\.\-\(\)]+|/[\w\s\.\-\(\)/]+)'
    paths = re.findall(path_pattern, content)
    raw_path = paths[0] if paths else "Path not found"
    full_path = raw_path
    if artifact_name.lower() not in raw_path.lower():
        sep = "/" if "/" in raw_path else "\\"
        full_path = f"{raw_path.rstrip(sep)}{sep}{artifact_name.lower()}"
    return {"time": times[0] if times else default_ts.get('modified', 'N/A'), "path": full_path}

def check_application(file_data):
    content = file_data.get("content", "").lower()
    ts_metadata = file_data.get("timestamps", {})
    results = []
    app_indicators = {
        "settings.json": "Tor Browser configuration file.",
        "places.sqlite": "Browser history/bookmarks database.",
        "cookies.sqlite": "Browser session cookies.",
        "noscript": "NoScript extension: Core Tor security component."
    }
    for artifact, reason in app_indicators.items():
        if artifact in content:
            ext = extract_internal_metadata(content, ts_metadata, artifact)
            results.append({
                "layer": "Application", "status": "Detected", "file_name": artifact.upper(),
                "file_path": ext["path"], "message": reason,
                "disk_timestamps": {"modified": ext["time"]}
            })
    return results
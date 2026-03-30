import os
import sys
import tempfile


APP_NAME = "TorTraceAnalyzer"


def resource_path(relative_path):
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path


def get_user_data_dir():
    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        return ensure_dir(os.path.join(local_appdata, APP_NAME))
    return ensure_dir(os.path.join(os.path.expanduser("~"), f".{APP_NAME.lower()}"))


def get_runtime_dir():
    return ensure_dir(os.path.join(tempfile.gettempdir(), APP_NAME))


def get_case_file_path():
    return os.path.join(get_user_data_dir(), "cases.json")


def get_temp_graph_path(filename="timeline_graph.png"):
    return os.path.join(get_runtime_dir(), filename)

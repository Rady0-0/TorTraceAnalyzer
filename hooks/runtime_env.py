import os
import tempfile


runtime_root = os.path.join(tempfile.gettempdir(), "TorTraceAnalyzer")
cache_root = os.path.join(runtime_root, "cache")
matplotlib_root = os.path.join(runtime_root, "matplotlib")

os.makedirs(cache_root, exist_ok=True)
os.makedirs(matplotlib_root, exist_ok=True)

os.environ.setdefault("XDG_CACHE_HOME", cache_root)
os.environ.setdefault("MPLCONFIGDIR", matplotlib_root)

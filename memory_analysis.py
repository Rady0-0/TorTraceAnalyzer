def check_memory(file):

    try:
        with open(file, "r") as f:
            data = f.read().lower()

        if "tor.exe" in data:
            return "[Memory Layer] Tor process detected"

        else:
            return "[Memory Layer] No Tor process detected"

    except FileNotFoundError:
        return "[Memory Layer] Memory file not found"
import os

from memory_analysis import check_memory
from system_analysis import check_system
from network_analysis import check_network
from application_analysis import check_application


print("===== TorTraceAnalyzer =====")
print("Scanning forensic input folder...\n")

folder = "input_data"

# Artifact indicators
memory_indicators = ["pid", "process", "tor.exe", "firefox.exe"]
system_indicators = ["prefetch", ".pf", "last run time"]
network_indicators = ["tls", "tcp", "udp", "relay"]
application_indicators = ["sqlite", "places.sqlite", "cookies.sqlite", "tor browser"]


for file in os.listdir(folder):

    filepath = os.path.join(folder, file)

    if os.path.isfile(filepath):

        print("Analyzing:", file)

        try:
            with open(filepath, "r", errors="ignore") as f:
                data = f.read().lower()

        except:
            print("Unable to read file\n")
            continue

        # Memory layer detection
        if any(indicator in data for indicator in memory_indicators):
            print(check_memory(filepath))

        # System layer detection
        elif any(indicator in data for indicator in system_indicators):
            print(check_system(filepath))

        # Network layer detection
        elif any(indicator in data for indicator in network_indicators):
            print(check_network(filepath))

        # Application layer detection
        elif any(indicator in data for indicator in application_indicators):
            print(check_application(filepath))

        else:
            print("No relevant forensic artifacts detected")

        print()
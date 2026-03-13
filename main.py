from memory_analysis import check_memory

print("===== TorTraceAnalyzer =====")
print("Starting forensic artifact analysis...\n")

result = check_memory("sample_data/pslist.txt")

print(result)
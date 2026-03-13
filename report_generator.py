def generate_report(results, correlations, score, level):

    report = []
    
    report.append("========================================")
    report.append("        TORTRACEANALYZER REPORT")
    report.append("========================================\n")

    report.append("LAYER DETECTION RESULTS")
    report.append("----------------------------------------")

    for layer, detected in results.items():
        status = "Detected" if detected else "Not Detected"
        report.append(f"{layer.capitalize()} Layer : {status}")

    report.append("\nARTIFACT CORRELATION")
    report.append("----------------------------------------")

    for c in correlations:
        report.append("* " + c)

    report.append("\nRISK ASSESSMENT")
    report.append("----------------------------------------")

    report.append(f"Tor Activity Risk Score : {score}")
    report.append(f"Confidence Level : {level}")

    report.append("\n========================================")
    report.append("End of Report")
    report.append("========================================")

    report_text = "\n".join(report)

    with open("tortrace_report.txt", "w") as f:
        f.write(report_text)

    print("\nReport generated: tortrace_report.txt")
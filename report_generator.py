import datetime
import json
import os

import pandas as pd
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer

from app_paths import get_user_data_dir


def _ensure_parent_dir(file_path):
    parent_dir = os.path.dirname(file_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)


def generate_report(
    all_detections,
    fci_score,
    determination,
    correlation_summary,
    timeline_data,
    case_info=None,
    notes=None,
    target_path=None,
):
    if target_path:
        full_path = target_path
    else:
        report_dir = _get_smart_path()
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        full_path = os.path.join(report_dir, f"TorTrace_Report_{timestamp}.txt")

    _ensure_parent_dir(full_path)

    with open(full_path, "w", encoding="utf-8") as report_file:
        report_file.write("=" * 100 + "\n")
        report_file.write("TORTRACE ANALYZER - FORENSIC REPORT".center(100) + "\n")
        report_file.write(
            ("Generated: " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")).center(100) + "\n"
        )
        report_file.write("=" * 100 + "\n\n")

        report_file.write("EXECUTIVE SUMMARY\n")
        report_file.write("-" * 100 + "\n")
        report_file.write(f"FCI SCORE       : {fci_score:.2f}%\n")
        report_file.write(f"DETERMINATION   : {determination}\n")
        report_file.write(f"CORRELATION     : {correlation_summary}\n\n")

        report_file.write("TIMELINE\n")
        report_file.write("-" * 100 + "\n")
        for event in timeline_data.get("events", []):
            report_file.write(
                f"{event.get('time')} | {event.get('layer')} | {event.get('artifact')} | {event.get('type')}\n"
            )
        report_file.write("\n")

        if notes:
            report_file.write("INVESTIGATOR NOTES\n")
            report_file.write("-" * 100 + "\n")
            report_file.write(notes + "\n\n")

        report_file.write("DETAILED FINDINGS\n")
        report_file.write("-" * 100 + "\n")
        for detection in all_detections:
            timestamps = detection.get("disk_timestamps", {})
            report_file.write(f"\n[{detection.get('layer')}] {detection.get('file_name')}\n")
            report_file.write(f"Path     : {detection.get('file_path')}\n")
            report_file.write(f"Evidence : {detection.get('evidence_match')}\n")
            report_file.write(f"Modified : {timestamps.get('modified')}\n")
            report_file.write(f"Note     : {detection.get('message')}\n")
            report_file.write("-" * 80)

    return full_path


def export_pdf_report(
    all_detections,
    fci_score,
    determination,
    correlation_summary,
    timeline_data,
    target_path,
    case_info=None,
    graph_path=None,
    notes=None,
):
    if not target_path.lower().endswith(".pdf"):
        target_path += ".pdf"

    _ensure_parent_dir(target_path)

    doc = SimpleDocTemplate(target_path)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("TORTRACE FORENSIC REPORT", styles["Title"]))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("<b>Executive Summary</b>", styles["Heading2"]))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(f"FCI Score: {fci_score}%", styles["Normal"]))
    elements.append(Paragraph(f"Determination: {determination}", styles["Normal"]))
    elements.append(Paragraph(f"Correlation: {correlation_summary}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("<b>Timeline</b>", styles["Heading2"]))
    elements.append(Spacer(1, 8))
    events = timeline_data.get("events", [])
    if not events:
        elements.append(Paragraph("No timeline data available.", styles["Normal"]))
    else:
        for event in events:
            line = f"{event.get('time')} -> {event.get('layer')} -> {event.get('artifact')}"
            elements.append(Paragraph(line, styles["Normal"]))

    elements.append(Spacer(1, 12))
    if graph_path and os.path.exists(graph_path):
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("<b>Timeline Graph</b>", styles["Heading2"]))
        elements.append(Spacer(1, 10))
        elements.append(Image(graph_path, width=500, height=250))

    if notes:
        elements.append(Spacer(1, 12))
        elements.append(Paragraph("<b>Investigator Notes</b>", styles["Heading2"]))
        elements.append(Spacer(1, 8))
        elements.append(Paragraph(notes, styles["Normal"]))

    elements.append(Paragraph("<b>Detailed Findings</b>", styles["Heading2"]))
    elements.append(Spacer(1, 8))
    for detection in all_detections:
        timestamps = detection.get("disk_timestamps", {})
        elements.append(Paragraph(f"[{detection.get('layer')}] {detection.get('file_name')}", styles["Heading3"]))
        elements.append(Paragraph(f"Path: {detection.get('file_path')}", styles["Normal"]))
        elements.append(Paragraph(f"Evidence: {detection.get('evidence_match')}", styles["Normal"]))
        elements.append(Paragraph(f"Modified: {timestamps.get('modified')}", styles["Normal"]))
        elements.append(Paragraph(f"Note: {detection.get('message')}", styles["Normal"]))
        elements.append(Spacer(1, 10))

    doc.build(elements)
    return target_path


def export_custom_report(
    all_detections,
    fci_score,
    determination,
    correlation_summary,
    timeline_data,
    format_type,
    target_path,
    case_info=None,
    notes=None,
):
    format_type = format_type.upper()
    _ensure_parent_dir(target_path)

    flat_data = []
    for detection in all_detections:
        timestamps = detection.get("disk_timestamps", {})
        flat_data.append(
            {
                "Layer": detection.get("layer"),
                "Artifact": detection.get("file_name"),
                "Modified": timestamps.get("modified"),
                "Evidence": detection.get("evidence_match"),
                "Path": detection.get("file_path"),
            }
        )

    df_evidence = pd.DataFrame(flat_data)
    df_timeline = pd.DataFrame(timeline_data.get("events", []))

    if format_type == "EXCEL":
        with pd.ExcelWriter(target_path, engine="openpyxl") as writer:
            df_evidence.to_excel(writer, sheet_name="Evidence", index=False)
            df_timeline.to_excel(writer, sheet_name="Timeline", index=False)
            if notes:
                pd.DataFrame([{"Notes": notes}]).to_excel(writer, sheet_name="Notes", index=False)
    elif format_type == "CSV":
        df_evidence.to_csv(target_path, index=False)
        if notes:
            notes_path = os.path.splitext(target_path)[0] + "_notes.txt"
            with open(notes_path, "w", encoding="utf-8") as notes_file:
                notes_file.write(notes)
    elif format_type == "JSON":
        with open(target_path, "w", encoding="utf-8") as json_file:
            json.dump(
                {
                    "summary": {"fci": fci_score, "determination": determination},
                    "timeline": timeline_data.get("events", []),
                    "evidence": flat_data,
                    "notes": notes,
                },
                json_file,
                indent=4,
            )
    elif format_type == "TXT":
        return generate_report(
            all_detections,
            fci_score,
            determination,
            correlation_summary,
            timeline_data,
            case_info,
            notes,
            target_path,
        )
    elif format_type == "PDF":
        return export_pdf_report(
            all_detections,
            fci_score,
            determination,
            correlation_summary,
            timeline_data,
            target_path,
            case_info,
            case_info.get("graph_path") if case_info else None,
            notes,
        )

    return target_path


def _get_smart_path():
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    if not os.path.exists(desktop_path):
        desktop_path = os.path.join(os.path.expanduser("~"), "OneDrive", "Desktop")
    if os.path.exists(desktop_path):
        return desktop_path
    return get_user_data_dir()

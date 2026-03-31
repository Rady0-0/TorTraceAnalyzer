import datetime
import json
import os

import pandas as pd
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer

from app_paths import get_user_data_dir


CASE_FIELDS = [
    ("Case Name", "case_name"),
    ("Case ID", "case_id"),
    ("Investigator", "investigator"),
    ("Organization", "organization"),
    ("Department", "department"),
    ("Contact Email", "contact_email"),
    ("Description", "case_description"),
]


def _ensure_parent_dir(file_path):
    parent_dir = os.path.dirname(file_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)


def _case_lines(case_info):
    case_info = case_info or {}
    lines = []
    for label, key in CASE_FIELDS:
        value = str(case_info.get(key, "")).strip()
        if value:
            lines.append((label, value))
    return lines


def _normalize_visual_paths(visual_paths=None, graph_path=None):
    visuals = []
    for visual in visual_paths or []:
        title = visual.get("title")
        path = visual.get("path")
        if title and path and os.path.exists(path):
            visuals.append({"title": title, "path": path})

    if not visuals and graph_path and os.path.exists(graph_path):
        visuals.append({"title": "Timeline Graph", "path": graph_path})

    return visuals


def _format_correlation_item(item):
    parts = [part.strip() for part in str(item).split("|", 2)]
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    text = str(item).strip()
    severity = text.split(":", 1)[0].strip() if ":" in text else "INFO"
    explanation = text.split(":", 1)[1].strip() if ":" in text else text
    return severity, "Correlation finding", explanation


def generate_report(
    all_detections,
    fci_score,
    determination,
    correlation_summary,
    timeline_data,
    case_info=None,
    notes=None,
    target_path=None,
    correlation_items=None,
):
    if target_path:
        full_path = target_path
    else:
        report_dir = _get_smart_path()
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        full_path = os.path.join(report_dir, f"TorTrace_Report_{timestamp}.txt")

    _ensure_parent_dir(full_path)
    case_lines = _case_lines(case_info)

    with open(full_path, "w", encoding="utf-8") as report_file:
        report_file.write("=" * 100 + "\n")
        report_file.write("TORTRACE ANALYZER - FORENSIC REPORT".center(100) + "\n")
        report_file.write(
            ("Generated: " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")).center(100) + "\n"
        )
        report_file.write("=" * 100 + "\n\n")

        if case_lines:
            report_file.write("CASE INFORMATION\n")
            report_file.write("-" * 100 + "\n")
            for label, value in case_lines:
                report_file.write(f"{label:<15}: {value}\n")
            report_file.write("\n")

        report_file.write("EXECUTIVE SUMMARY\n")
        report_file.write("-" * 100 + "\n")
        report_file.write(f"FCI SCORE       : {fci_score:.2f}%\n")
        report_file.write(f"DETERMINATION   : {determination}\n")
        report_file.write(f"CORRELATION     : {correlation_summary}\n\n")

        if correlation_items:
            report_file.write("CORRELATION FINDINGS\n")
            report_file.write("-" * 100 + "\n")
            for item in correlation_items:
                severity, title, explanation = _format_correlation_item(item)
                report_file.write(f"[{severity}] {title}\n")
                report_file.write(f"  {explanation}\n")
            report_file.write("\n")

        report_file.write("TIMELINE\n")
        report_file.write("-" * 100 + "\n")
        summary = timeline_data.get("summary")
        if summary:
            report_file.write(summary + "\n")
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
            report_file.write(f"Created  : {timestamps.get('created')}\n")
            report_file.write(f"Accessed : {timestamps.get('accessed')}\n")
            report_file.write(f"Note     : {detection.get('message')}\n")
            report_file.write("-" * 80 + "\n")

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
    visual_paths=None,
    correlation_items=None,
):
    if not target_path.lower().endswith(".pdf"):
        target_path += ".pdf"

    _ensure_parent_dir(target_path)

    doc = SimpleDocTemplate(target_path)
    styles = getSampleStyleSheet()
    elements = []
    case_lines = _case_lines(case_info)
    visuals = _normalize_visual_paths(visual_paths=visual_paths, graph_path=graph_path)

    elements.append(Paragraph("TORTRACE FORENSIC REPORT", styles["Title"]))
    elements.append(Spacer(1, 12))

    if case_lines:
        elements.append(Paragraph("<b>Case Information</b>", styles["Heading2"]))
        elements.append(Spacer(1, 8))
        for label, value in case_lines:
            elements.append(Paragraph(f"{label}: {value}", styles["Normal"]))
        elements.append(Spacer(1, 12))

    elements.append(Paragraph("<b>Executive Summary</b>", styles["Heading2"]))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(f"FCI Score: {fci_score}%", styles["Normal"]))
    elements.append(Paragraph(f"Determination: {determination}", styles["Normal"]))
    elements.append(Paragraph(f"Correlation: {correlation_summary}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    if correlation_items:
        elements.append(Paragraph("<b>Correlation Findings</b>", styles["Heading2"]))
        elements.append(Spacer(1, 8))
        for item in correlation_items:
            severity, title, explanation = _format_correlation_item(item)
            elements.append(Paragraph(f"[{severity}] {title}", styles["Normal"]))
            elements.append(Paragraph(explanation, styles["Normal"]))
        elements.append(Spacer(1, 12))

    elements.append(Paragraph("<b>Timeline</b>", styles["Heading2"]))
    elements.append(Spacer(1, 8))
    events = timeline_data.get("events", [])
    if timeline_data.get("summary"):
        elements.append(Paragraph(timeline_data.get("summary"), styles["Normal"]))
        elements.append(Spacer(1, 6))
    if not events:
        elements.append(Paragraph("No timeline data available.", styles["Normal"]))
    else:
        for event in events[:30]:
            line = f"{event.get('time')} -> {event.get('layer')} -> {event.get('artifact')} -> {event.get('type')}"
            elements.append(Paragraph(line, styles["Normal"]))
        if len(events) > 30:
            elements.append(Paragraph(f"... {len(events) - 30} more timeline events omitted from this section.", styles["Normal"]))

    elements.append(Spacer(1, 12))
    if visuals:
        elements.append(Paragraph("<b>Visualizations</b>", styles["Heading2"]))
        elements.append(Spacer(1, 8))
        for visual in visuals:
            elements.append(Paragraph(visual["title"], styles["Heading3"]))
            elements.append(Spacer(1, 6))
            elements.append(Image(visual["path"], width=480, height=260))
            elements.append(Spacer(1, 12))

    if notes:
        elements.append(Paragraph("<b>Investigator Notes</b>", styles["Heading2"]))
        elements.append(Spacer(1, 8))
        elements.append(Paragraph(notes, styles["Normal"]))
        elements.append(Spacer(1, 12))

    elements.append(Paragraph("<b>Detailed Findings</b>", styles["Heading2"]))
    elements.append(Spacer(1, 8))
    for detection in all_detections:
        timestamps = detection.get("disk_timestamps", {})
        elements.append(Paragraph(f"[{detection.get('layer')}] {detection.get('file_name')}", styles["Heading3"]))
        elements.append(Paragraph(f"Path: {detection.get('file_path')}", styles["Normal"]))
        elements.append(Paragraph(f"Evidence: {detection.get('evidence_match')}", styles["Normal"]))
        elements.append(Paragraph(f"Modified: {timestamps.get('modified')}", styles["Normal"]))
        elements.append(Paragraph(f"Created: {timestamps.get('created')}", styles["Normal"]))
        elements.append(Paragraph(f"Accessed: {timestamps.get('accessed')}", styles["Normal"]))
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
    visual_paths=None,
    correlation_items=None,
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
                "Created": timestamps.get("created"),
                "Accessed": timestamps.get("accessed"),
                "Evidence": detection.get("evidence_match"),
                "Path": detection.get("file_path"),
                "Message": detection.get("message"),
            }
        )

    df_evidence = pd.DataFrame(flat_data)
    df_timeline = pd.DataFrame(timeline_data.get("events", []))
    df_case = pd.DataFrame([{label: value for label, value in _case_lines(case_info)}]) if _case_lines(case_info) else pd.DataFrame()
    df_correlation = pd.DataFrame({"Correlation": correlation_items or []})

    if format_type == "EXCEL":
        with pd.ExcelWriter(target_path, engine="openpyxl") as writer:
            if not df_case.empty:
                df_case.to_excel(writer, sheet_name="Case", index=False)
            df_evidence.to_excel(writer, sheet_name="Evidence", index=False)
            df_timeline.to_excel(writer, sheet_name="Timeline", index=False)
            if not df_correlation.empty:
                df_correlation.to_excel(writer, sheet_name="Correlation", index=False)
            if notes:
                pd.DataFrame([{"Notes": notes}]).to_excel(writer, sheet_name="Notes", index=False)
    elif format_type == "CSV":
        df_evidence.to_csv(target_path, index=False)
        summary_path = os.path.splitext(target_path)[0] + "_summary.txt"
        with open(summary_path, "w", encoding="utf-8") as summary_file:
            for label, value in _case_lines(case_info):
                summary_file.write(f"{label}: {value}\n")
            summary_file.write(f"FCI Score: {fci_score}\n")
            summary_file.write(f"Determination: {determination}\n")
            summary_file.write(f"Correlation: {correlation_summary}\n")
            if notes:
                summary_file.write("\nNotes:\n")
                summary_file.write(notes)
    elif format_type == "JSON":
        with open(target_path, "w", encoding="utf-8") as json_file:
            json.dump(
                {
                    "case_info": case_info or {},
                    "summary": {
                        "fci": fci_score,
                        "determination": determination,
                        "correlation_summary": correlation_summary,
                        "correlation_items": correlation_items or [],
                    },
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
            case_info=case_info,
            notes=notes,
            target_path=target_path,
            correlation_items=correlation_items,
        )
    elif format_type == "PDF":
        return export_pdf_report(
            all_detections,
            fci_score,
            determination,
            correlation_summary,
            timeline_data,
            target_path,
            case_info=case_info,
            graph_path=case_info.get("graph_path") if case_info else None,
            notes=notes,
            visual_paths=visual_paths,
            correlation_items=correlation_items,
        )

    return target_path


def _get_smart_path():
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    if not os.path.exists(desktop_path):
        desktop_path = os.path.join(os.path.expanduser("~"), "OneDrive", "Desktop")
    if os.path.exists(desktop_path):
        return desktop_path
    return get_user_data_dir()

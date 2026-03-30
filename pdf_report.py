from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def generate_pdf_report(all_detections, fci, determination, summary, timeline, path):

    doc = SimpleDocTemplate(path)
    styles = getSampleStyleSheet()

    content = []

    content.append(Paragraph("TORTRACE FORENSIC REPORT", styles['Title']))
    content.append(Spacer(1, 10))

    content.append(Paragraph(f"FCI: {fci}%", styles['Normal']))
    content.append(Paragraph(f"Determination: {determination}", styles['Normal']))
    content.append(Paragraph(summary, styles['Normal']))

    content.append(Spacer(1, 10))

    for d in all_detections:
        content.append(Paragraph(f"{d['file_name']} - {d['file_path']}", styles['Normal']))

    doc.build(content)
"""Visualization module for ForensicX"""
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
from pathlib import Path
import logging
import xml.sax.saxutils as saxutils

from .config import REPORTS_DIR

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from datetime import datetime

logger = logging.getLogger(__name__)

def escape_html(text):
    return saxutils.escape(str(text) if text is not None else "")

def make_severity_pie_chart(output_path: str, metrics: dict):
    labels = []
    sizes = []
    severity_order = ['critical', 'high', 'medium', 'low']
    color_map = {'critical': '#E74C3C', 'high': '#F39C12', 'medium': '#3498DB', 'low': '#27AE60'}
    for sev in severity_order:
        count = metrics.get(f"{sev}_count", 0)
        if count > 0:
            labels.append(sev.capitalize())
            sizes.append(count)
    colors = [color_map[sev] for sev in severity_order if metrics.get(f"{sev}_count", 0) > 0]
    if sum(sizes) == 0: return None
    plt.figure(figsize=(4, 4), facecolor='white')
    plt.pie(sizes, labels=labels, colors=colors, autopct='%1.0f%%', startangle=140)
    plt.title("Incident Severity Distribution")
    plt.tight_layout()
    plt.savefig(output_path, bbox_inches='tight', facecolor='white')
    plt.close()
    return output_path

def make_timeline_chart(output_path: str, incidents: list):
    if not incidents: return None
    severities = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    x_vals = list(range(1, len(incidents) + 1))
    y_vals = [severities.get(inc.get('severity', 'low').lower(), 1) for inc in incidents]
    plt.figure(figsize=(6, 2.6), facecolor='white')
    plt.plot(x_vals, y_vals, marker='o', color='#FF6B5B', linewidth=2)
    plt.fill_between(x_vals, y_vals, color='orange', alpha=0.1)
    plt.yticks(list(severities.values()), ['Low', 'Medium', 'High', 'Critical'])
    plt.xlabel('Incident Number')
    plt.ylabel('Severity')
    plt.title('Incident Severity Timeline')
    plt.tight_layout()
    plt.savefig(output_path, bbox_inches='tight', facecolor='white')
    plt.close()
    return output_path

"""
PDF Report Generator for ForensicX; embeds graphs if present in REPORTS_DIR.
'IOC Distribution' graph always starts on a new page.
"""

def generate_pdf_report(log_id, analysis_data):
    try:
        from .config import REPORTS_DIR
    except Exception:
        REPORTS_DIR = Path('reports')
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    pdf_path = REPORTS_DIR / f"forensicx_report_{log_id}.pdf"

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch
    )
    elements = []

    # Styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'Title', parent=styles['Heading1'], fontSize=24,
        textColor=colors.HexColor('#1F2A3E'), spaceAfter=8, alignment=TA_CENTER, fontName='Helvetica-Bold'
    )
    heading_style = ParagraphStyle(
        'Heading', parent=styles['Heading2'], fontSize=13,
        textColor=colors.HexColor('#2E5090'), spaceAfter=10, spaceBefore=14, fontName='Helvetica-Bold'
    )
    normal_style = ParagraphStyle(
        'Normal', parent=styles['Normal'], fontSize=10,
        alignment=TA_JUSTIFY, spaceAfter=8, leading=14
    )
    table_header_bg = colors.HexColor("#E9EDF4")
    table_alt_bg = [colors.HexColor('#F5F8FA'), colors.white]

    # TITLE PAGE
    elements.append(Paragraph("Forensic Analysis Report", title_style))
    elements.append(Spacer(1, 0.1*inch))
    filename = escape_html(analysis_data.get('filename', 'Unknown'))
    timestamp = escape_html(analysis_data.get('timestamp', datetime.now().isoformat()))
    metadata_data = [
        ['Report Date', timestamp],
        ['Log File', filename],
        ['Analysis ID', escape_html(analysis_data.get('log_id', ''))],
        ['Generated On', datetime.now().strftime('%Y-%m-%d %H:%M')]
    ]
    metadata_table = Table(metadata_data, colWidths=[1.7*inch, 4.3*inch])
    metadata_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (1, 0), table_header_bg),
        ('FONT', (0, 0), (-1, -1), 'Helvetica', 9),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#1F2A3E')),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (1, -1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), table_alt_bg),
        ('GRID', (0, 0), (-1, -1), 0.4, colors.grey)
    ]))
    elements.append(metadata_table)
    elements.append(Spacer(1, 0.28*inch))

    # EXECUTIVE SUMMARY
    elements.append(Paragraph("Executive Summary", heading_style))
    summary_text = analysis_data.get('summary', 'No summary available')
    if isinstance(summary_text, dict):
        summary_text = summary_text.get('executive', 'No summary available')
    elements.append(Paragraph(escape_html(summary_text), normal_style))
    elements.append(Spacer(1, 0.18*inch))

    # KEY METRICS
    elements.append(Paragraph("Key Metrics", heading_style))
    file_metrics = analysis_data.get('file_metrics', {})
    metrics_data = [
        ['Metric', 'Value'],
        ['Total Events Analyzed', str(file_metrics.get('events_count', 0))],
        ['Total Incidents Detected', str(file_metrics.get('total_incidents', 0))],
        ['Critical', str(file_metrics.get('critical_count', 0))],
        ['High', str(file_metrics.get('high_count', 0))],
        ['Medium', str(file_metrics.get('medium_count', 0))],
        ['Low', str(file_metrics.get('low_count', 0))],
        ['Indicators of Compromise', str(file_metrics.get('ioc_count', 0))]
    ]
    metrics_table = Table(metrics_data, colWidths=[2.2*inch, 3.1*inch])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), table_header_bg),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1F2A3E')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.3, colors.darkgrey),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), table_alt_bg),
    ]))
    elements.append(metrics_table)
    elements.append(Spacer(1, 0.2*inch))

    # FINDINGS / INCIDENTS
    elements.append(Paragraph("Findings (Detected Incidents)", heading_style))
    incidents = analysis_data.get('incidents', [])
    if incidents:
        for idx, incident in enumerate(incidents[:20], 1):
            inc_type = incident.get('type', 'Unknown')
            severity = incident.get('severity', 'unknown').capitalize()
            detail = incident.get('detail', 'No details')
            confidence = incident.get('confidence', 'N/A')
            header = f"<b>[{escape_html(severity)}]</b> {escape_html(inc_type)} (Confidence: {escape_html(confidence)}%)"
            elements.append(Paragraph(header, normal_style))
            elements.append(Paragraph(escape_html(detail), normal_style))
            elements.append(Spacer(1, 0.07*inch))
    else:
        elements.append(Paragraph("No incidents detected in this log file.", normal_style))
    elements.append(Spacer(1, 0.13*inch))

    # IOCs TABLE
    elements.append(Paragraph("Indicators of Compromise (IOCs)", heading_style))
    iocs = analysis_data.get('iocs', [])
    if iocs:
        ioc_data = [['Type', 'Indicator', 'Severity']]
        for ioc in iocs[:15]:
            if isinstance(ioc, dict):
                ioc_type = ioc.get('type') or 'Unknown'
                ioc_value = ioc.get('value') or str(ioc)
            elif isinstance(ioc, str) and ':' in ioc:
                parts = ioc.split(':', 1)
                ioc_type = parts[0].strip()
                ioc_value = parts[1].strip()
            else:
                ioc_type = 'Unknown'
                ioc_value = str(ioc)
            ioc_data.append([escape_html(ioc_type), escape_html(ioc_value), 'High'])
        ioc_table = Table(ioc_data, colWidths=[1.4*inch, 3.4*inch, 1.1*inch])
        ioc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), table_header_bg),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#2E5090')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), table_alt_bg),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.darkgrey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(ioc_table)
    else:
        elements.append(Paragraph("No IOCs identified in this log file.", normal_style))
    elements.append(Spacer(1, 0.18*inch))
    elements.append(PageBreak())

    # RECOMMENDATIONS
    elements.append(Paragraph("Recommendations & Mitigation Strategies", heading_style))
    recommendations = analysis_data.get('recommendations', [])
    if recommendations:
        for idx, rec in enumerate(recommendations, 1):
            rec_text = f"<b>Priority {idx}:</b> {escape_html(rec)}"
            elements.append(Paragraph(rec_text, normal_style))
            elements.append(Spacer(1, 0.08*inch))
    else:
        elements.append(Paragraph("No recommendations available.", normal_style))
    elements.append(Spacer(1, 0.2*inch))

    # ===== ALIGNED GRAPHS SECTION WITH PAGEBREAK BEFORE 'IOC Distribution' =====
    elements.append(PageBreak())
    elements.append(Paragraph("Graphs & Visualizations", title_style))
    elements.append(Spacer(1, 0.2*inch))
    graph_base_path = REPORTS_DIR

    graph_defs = [
        ("Severity Distribution", f"{log_id}_severity.png"),
        ("Incident Timeline", f"{log_id}_timeline.png"),
        ("IOC Distribution", f"{log_id}_ioc.png"),
        ("Affected Systems", f"{log_id}_systems.png"),
    ]
    for idx, (heading, filename) in enumerate(graph_defs):
        # Add extra PageBreak before IOC Distribution graph
        if heading == "IOC Distribution":
            elements.append(PageBreak())
        elements.append(Paragraph(heading, heading_style))
        elements.append(Spacer(1, 0.10*inch))
        graph_path = graph_base_path / filename
        if graph_path.exists():
            elements.append(Image(str(graph_path), width=5.2*inch, height=3.2*inch))
        else:
            elements.append(Paragraph(f"{heading} chart not available.", normal_style))
        elements.append(Spacer(1, 0.12*inch))
    # ===== END GRAPHS SECTION =====

    # SUMMARY STATS SECTION
    elements.append(PageBreak())
    elements.append(Paragraph("Analysis Summary Stats", heading_style))
    summary_stats = escape_html(analysis_data.get('summary_stats', ''))
    analysis_time = analysis_data.get('analysis_time', 0)
    try:
        analysis_time_num = float(analysis_time)
    except Exception:
        analysis_time_num = 0.0
    file_size = analysis_data.get('file_size', 0)
    try:
        file_size_num = float(file_size)
    except Exception:
        file_size_num = 0.0
    total_lines = analysis_data.get('total_lines', 0)
    try:
        total_lines_num = int(total_lines)
    except Exception:
        total_lines_num = 0
    summary_text_final = (
        f"<b>Analysis Statistics:</b><br/>"
        f"{summary_stats}<br/><br/>"
        f"<b>Analysis Duration:</b> {analysis_time_num:.2f} seconds<br/>"
        f"<b>File Size:</b> {file_size_num/1024:.2f} KB<br/>"
        f"<b>Total Lines Analyzed:</b> {total_lines_num}<br/>"
    )
    elements.append(Paragraph(summary_text_final, normal_style))
    elements.append(Spacer(1, 0.3*inch))

    # FOOTER
    footer_text = "<i>This report was automatically generated by ForensicX - Digital Forensic Analysis System v1.0.0</i>"
    elements.append(Paragraph(footer_text, ParagraphStyle(
        'Footer', parent=styles['Normal'], fontSize=8, textColor=colors.darkgray, alignment=TA_CENTER
    )))

    try:
        doc.build(elements)
        print(f"✅ PDF Report generated: {pdf_path}")
        return str(pdf_path)
    except Exception as e:
        print(f"❌ PDF generation error: {e}")
        import traceback
        traceback.print_exc()
        return None

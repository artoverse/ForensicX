"""Visualization and report generation module"""
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
from datetime import datetime
from pathlib import Path

def make_severity_pie_chart(path, metrics):
    """Generate severity distribution pie chart"""
    labels = []
    sizes = []
    
    if metrics.get('critical_count', 0) > 0:
        labels.append(f"Critical ({metrics['critical_count']})")
        sizes.append(metrics['critical_count'])
    if metrics.get('high_count', 0) > 0:
        labels.append(f"High ({metrics['high_count']})")
        sizes.append(metrics['high_count'])
    if metrics.get('medium_count', 0) > 0:
        labels.append(f"Medium ({metrics['medium_count']})")
        sizes.append(metrics['medium_count'])
    if metrics.get('low_count', 0) > 0:
        labels.append(f"Low ({metrics['low_count']})")
        sizes.append(metrics['low_count'])
    
    if not sizes:
        labels = ['No Incidents']
        sizes = [1]
    
    colors = ['#FF6B6B', '#FFA500', '#4ECDC4', '#95E1D3'][:len(sizes)]
    
    fig, ax = plt.subplots(figsize=(8, 6))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, autopct='%1.1f%%',
        colors=colors, startangle=140
    )
    ax.set_title('Severity Distribution', fontsize=14, fontweight='bold')
    
    for autotext in autotexts:
        autotext.set_color('white')
        autotext.set_fontweight('bold')
    
    fig.tight_layout()
    fig.savefig(path, dpi=100, bbox_inches='tight')
    plt.close(fig)

def make_timeline_chart(path, incidents):
    """Generate incident timeline chart"""
    if not incidents:
        incidents = [{'severity': 'low'}]
    
    severity_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    x = list(range(len(incidents)))
    y = [severity_map.get(i.get('severity', 'low'), 1) for i in incidents]
    
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(x, y, marker='o', linestyle='-', color='#FF6B6B', linewidth=2, markersize=6)
    ax.fill_between(x, y, alpha=0.3, color='#FF6B6B')
    ax.set_xlabel('Incident Number', fontsize=10)
    ax.set_ylabel('Severity Level', fontsize=10)
    ax.set_title('Incident Timeline', fontsize=14, fontweight='bold')
    ax.set_ylim(0, 5)
    ax.grid(True, alpha=0.3)
    
    fig.tight_layout()
    fig.savefig(path, dpi=100, bbox_inches='tight')
    plt.close(fig)

def generate_pdf_report(path, analysis_data):
    """Generate PDF report using FPDF"""
    try:
        from fpdf import FPDF
        
        pdf = FPDF()
        pdf.add_page()
        
        # Title
        pdf.set_font('Helvetica', 'B', 16)
        pdf.cell(0, 10, 'ForensicX Analysis Report', ln=True, align='C')
        
        # Case info
        pdf.set_font('Helvetica', '', 10)
        pdf.cell(0, 5, f"Analysis ID: {analysis_data.get('log_id', 'N/A')}", ln=True)
        pdf.cell(0, 5, f"File: {analysis_data.get('filename', 'N/A')}", ln=True)
        pdf.cell(0, 5, f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        pdf.ln(5)
        
        # Summary
        pdf.set_font('Helvetica', 'B', 12)
        pdf.cell(0, 8, 'Summary', ln=True)
        pdf.set_font('Helvetica', '', 10)
        
        metrics = analysis_data.get('file_metrics', {})
        pdf.cell(0, 5, f"Total Events: {metrics.get('events_count', 0)}", ln=True)
        pdf.cell(0, 5, f"Total Incidents: {metrics.get('total_incidents', 0)}", ln=True)
        pdf.cell(0, 5, f"Critical: {metrics.get('critical_count', 0)}", ln=True)
        pdf.cell(0, 5, f"High: {metrics.get('high_count', 0)}", ln=True)
        pdf.cell(0, 5, f"Medium: {metrics.get('medium_count', 0)}", ln=True)
        pdf.cell(0, 5, f"Low: {metrics.get('low_count', 0)}", ln=True)
        pdf.ln(5)
        
        # Recommendations
        pdf.set_font('Helvetica', 'B', 12)
        pdf.cell(0, 8, 'Recommendations', ln=True)
        pdf.set_font('Helvetica', '', 10)
        
        recommendations = analysis_data.get('recommendations', [])
        for rec in recommendations:
            pdf.cell(0, 5, f"• {rec}", ln=True)
        
        pdf.output(str(path))
        return True
    except Exception as e:
        print(f"Error generating PDF: {e}")
        return False
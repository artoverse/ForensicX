"""Fixed FastAPI main application for ForensicX - PRODUCTION READY"""
from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import json
import traceback
import logging

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

from .utils import gen_id, save_analysis, list_analyses, get_analysis_by_id
from .analyzer import analyze_text
from .visualizer import make_severity_pie_chart, make_timeline_chart, generate_pdf_report
from .chat_manager import answer_question, get_chat_history, add_to_chat_history
from .config import DATA_DIR, LOGS_DIR, REPORTS_DIR, CHATS_DIR, FRONTEND_DIR
from .config import USE_LLM

# Initialize FastAPI
app = FastAPI(
    title="ForensicX",
    description="Digital Forensic Analysis System",
    version="1.0.0"
)

# CORS middleware - allow all for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_methods=['*'],
    allow_headers=['*']
)

# Create required directories
for d in [DATA_DIR, LOGS_DIR, REPORTS_DIR, CHATS_DIR]:
    d.mkdir(parents=True, exist_ok=True)
    logger.info(f"✓ Directory ready: {d}")

# ============================================================================
# HEALTH & STATUS ENDPOINTS
# ============================================================================

@app.get('/health')
def health_check():
    """Health check endpoint"""
    logger.info("Health check requested")
    return {
        'status': 'healthy',
        'version': '1.0.0',
        'llm_available': USE_LLM
    }

@app.get('/api/status')
def api_status():
    """Get system status"""
    try:
        analyses = list_analyses()
        total_events = sum(a.get('file_metrics', {}).get('events_count', 0) for a in analyses)
        total_critical = sum(a.get('file_metrics', {}).get('critical_count', 0) for a in analyses)
        
        return {
            'total_analyses': len(analyses),
            'total_events_analyzed': total_events,
            'total_critical_incidents': total_critical,
            'llm_enabled': USE_LLM
        }
    except Exception as e:
        logger.error(f"Status error: {e}")
        return {'error': str(e)}

# ============================================================================
# ANALYSIS ENDPOINTS
# ============================================================================

@app.get('/api/analyses')
def api_list_analyses():
    """List all analyses"""
    try:
        analyses = list_analyses()
        logger.info(f"Loaded {len(analyses)} analyses")
        
        total_files = len(analyses)
        total_events = sum(a.get('file_metrics', {}).get('events_count', 0) for a in analyses)
        total_critical = sum(a.get('file_metrics', {}).get('critical_count', 0) for a in analyses)
        
        summary = {
            'total_files': total_files,
            'total_events': total_events,
            'total_critical': total_critical
        }
        
        return {
            'analyses': analyses,
            'summary': summary
        }
    except Exception as e:
        logger.error(f"List analyses error: {e}")
        return {'analyses': [], 'summary': {'total_files': 0, 'total_events': 0, 'total_critical': 0}}

@app.get('/api/analysis/{log_id}')
def api_get_analysis(log_id: str):
    """Get specific analysis by ID"""
    try:
        logger.info(f"Fetching analysis: {log_id}")
        analysis = get_analysis_by_id(log_id)
        if not analysis:
            logger.warning(f"Analysis not found: {log_id}")
            raise HTTPException(status_code=404, detail='Analysis not found')
        return analysis
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post('/api/upload')
async def api_upload(file: UploadFile = File(...)):
    """Upload and analyze log file"""
    try:
        logger.info(f"Upload started: {file.filename}")
        
        # Read file
        content = await file.read()
        text = content.decode('utf-8', errors='ignore')
        logger.info(f"File read: {len(text)} characters")
        
        # Generate IDs
        log_id = gen_id()
        filename = file.filename or 'unknown'
        
        # Save uploaded file
        dest = LOGS_DIR / f"{log_id}_{filename}"
        dest.write_bytes(content)
        logger.info(f"File saved to: {dest}")
        
        # Analyze
        logger.info(f"Starting analysis for: {filename}")
        incidents, file_metrics, summary, iocs = analyze_text(filename, text)
        logger.info(f"Analysis complete. Found {len(incidents)} incidents")
        
        # Create analysis record
        record = {
            'log_id': log_id,
            'filename': filename,
            'total_lines': summary.get('lines', 0),
            'file_size': len(content),
            'incidents': incidents[:50],  # Top 50 incidents
            'file_metrics': file_metrics,
            'iocs': iocs,
            'recommendations': [
                'Isolate affected systems immediately',
                'Initiate incident response protocol',
                'Reset compromised credentials',
                'Review and update firewall rules',
                'Conduct threat hunt across infrastructure'
            ],
            'summary': f"Detected {file_metrics.get('total_incidents', 0)} incidents: "
                      f"{file_metrics.get('critical_count', 0)} Critical, "
                      f"{file_metrics.get('high_count', 0)} High severity",
            'analysis_time': round(summary.get('analysis_time', 0), 3)
        }
        
        # Save analysis
        save_analysis(record)
        logger.info(f"Analysis saved with ID: {log_id}")
        
        # Generate visualizations
        try:
            pie_chart = REPORTS_DIR / f"chart_severity_{log_id}.png"
            timeline_chart = REPORTS_DIR / f"chart_timeline_{log_id}.png"
            
            make_severity_pie_chart(str(pie_chart), file_metrics)
            make_timeline_chart(str(timeline_chart), incidents)
            logger.info(f"Charts generated for: {log_id}")
        except Exception as e:
            logger.warning(f"Chart generation error: {e}")
        
        # Generate PDF
        try:
            pdf_path = REPORTS_DIR / f"report_{log_id}.pdf"
            generate_pdf_report(str(pdf_path), record)
            logger.info(f"PDF report generated for: {log_id}")
        except Exception as e:
            logger.warning(f"PDF generation error: {e}")
        
        logger.info(f"Upload complete: {log_id}")
        return JSONResponse(content=record)
    
    except Exception as e:
        logger.error(f"Upload error: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# CHAT ENDPOINTS
# ============================================================================

@app.post('/api/chat/{log_id}')
async def api_chat(log_id: str, request: Request):
    """Chat endpoint for Q&A"""
    try:
        logger.info(f"Chat request for analysis: {log_id}")
        data = await request.json()
        question = data.get('question', '').strip()
        
        if not question:
            return {'error': 'Question required'}
        
        logger.info(f"Question: {question}")
        
        # Get answer
        answer = answer_question(log_id, question)
        
        # Save to history
        add_to_chat_history(log_id, 'user', question)
        add_to_chat_history(log_id, 'assistant', answer)
        
        logger.info(f"Answer provided for: {log_id}")
        return {
            'question': question,
            'answer': answer
        }
    except Exception as e:
        logger.error(f"Chat error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get('/api/chat/{log_id}/history')
def api_get_chat_history(log_id: str):
    """Get chat history for analysis"""
    try:
        history = get_chat_history(log_id)
        return {'messages': history}
    except Exception as e:
        logger.error(f"Chat history error: {e}")
        return {'messages': []}

# ============================================================================
# REPORT & CHART ENDPOINTS
# ============================================================================

@app.get('/api/report/{log_id}')
def api_get_report(log_id: str):
    """Download PDF report"""
    try:
        pdf_path = REPORTS_DIR / f"report_{log_id}.pdf"
        if pdf_path.exists():
            return FileResponse(
                pdf_path,
                media_type='application/pdf',
                filename=f"forensicx_report_{log_id}.pdf"
            )
        raise HTTPException(status_code=404, detail='Report not found')
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Report error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get('/api/chart/{chart_type}/{log_id}')
def api_get_chart(chart_type: str, log_id: str):
    """Get chart image"""
    try:
        if chart_type == 'severity':
            chart_path = REPORTS_DIR / f'chart_severity_{log_id}.png'
        elif chart_type == 'timeline':
            chart_path = REPORTS_DIR / f'chart_timeline_{log_id}.png'
        else:
            raise HTTPException(status_code=400, detail='Invalid chart type')
        
        if chart_path.exists():
            return FileResponse(chart_path, media_type='image/png')
        
        raise HTTPException(status_code=404, detail='Chart not found')
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Chart error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# STATIC FILES & FRONTEND
# ============================================================================

# Mount frontend at root
if FRONTEND_DIR.exists():
    logger.info(f"Mounting frontend from: {FRONTEND_DIR}")
    app.mount('/', StaticFiles(directory=str(FRONTEND_DIR), html=True), name='frontend')
else:
    logger.warning(f"Frontend directory not found: {FRONTEND_DIR}")

if __name__ == '__main__':
    logger.info("ForensicX Backend Ready")


"""Utility functions for ForensicX"""
import json
import uuid
from pathlib import Path
from datetime import datetime
from .config import DATA_DIR

def gen_id():
    """Generate a short unique identifier"""
    return uuid.uuid4().hex[:8]

def save_analysis(record):
    """Save analysis record to analyses.json"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    p = DATA_DIR / 'analyses.json'
    
    arr = []
    if p.exists():
        try:
            arr = json.loads(p.read_text(encoding='utf-8'))
        except (json.JSONDecodeError, IOError):
            arr = []
    
    # Add timestamp if not present
    if 'timestamp' not in record:
        record['timestamp'] = datetime.utcnow().isoformat()
    
    # Insert at beginning (most recent first)
    arr.insert(0, record)
    
    # Keep only last 100 analyses
    arr = arr[:100]
    
    p.write_text(json.dumps(arr, indent=2), encoding='utf-8')

def list_analyses():
    """Retrieve all analysis records"""
    p = DATA_DIR / 'analyses.json'
    if p.exists():
        try:
            return json.loads(p.read_text(encoding='utf-8'))
        except (json.JSONDecodeError, IOError):
            return []
    return []

def get_analysis_by_id(log_id):
    """Get specific analysis by ID"""
    analyses = list_analyses()
    for a in analyses:
        if a.get('log_id') == log_id:
            return a
    return None

def save_chat_history(log_id, messages):
    """Save chat history for an analysis"""
    from .config import CHATS_DIR
    CHATS_DIR.mkdir(parents=True, exist_ok=True)
    
    p = CHATS_DIR / f'chat_{log_id}.json'
    p.write_text(json.dumps({'messages': messages}, indent=2), encoding='utf-8')

def load_chat_history(log_id):
    """Load chat history for an analysis"""
    from .config import CHATS_DIR
    p = CHATS_DIR / f'chat_{log_id}.json'
    
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding='utf-8'))
            return data.get('messages', [])
        except (json.JSONDecodeError, IOError):
            return []
    return []
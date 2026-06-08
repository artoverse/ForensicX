"""Configuration module for ForensicX backend"""
from pathlib import Path
import os

# Base paths
ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / 'data'
LOGS_DIR = DATA_DIR / 'logs'
CHATS_DIR = DATA_DIR / 'chats'
REPORTS_DIR = DATA_DIR / 'reports'
MODELS_DIR = ROOT / 'models'

# Create directories (safe on both local and cloud)
for _d in [DATA_DIR, LOGS_DIR, CHATS_DIR, REPORTS_DIR, MODELS_DIR]:
    _d.mkdir(parents=True, exist_ok=True)

# API Configuration
API_HOST = os.getenv('API_HOST', '0.0.0.0')
API_PORT = int(os.getenv('PORT', os.getenv('API_PORT', 8000)))  # Render uses $PORT
API_RELOAD = os.getenv('API_RELOAD', 'false').lower() == 'true'  # Off in production

# Frontend path (served as static files by FastAPI)
FRONTEND_DIR = ROOT.parent / 'frontend' / 'public'

# LLM Configuration - auto-detect model; graceful fallback if not found
MODEL_PATH = None
if MODELS_DIR.exists():
    models = list(MODELS_DIR.glob('*.gguf'))
    if models:
        MODEL_PATH = models[0]
        print(f"Found model: {MODEL_PATH.name}")

USE_LLM = MODEL_PATH is not None
if USE_LLM:
    print(f"✅ LLM enabled: {MODEL_PATH.name}")
else:
    print("⚠️  LLM model not found — running in heuristic-only mode")
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

# Create directories
DATA_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)
CHATS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# LLM Configuration
MODEL_PATH = MODELS_DIR / 'Phi-3-mini-4k-instruct-q4.gguf'
USE_LLM = MODEL_PATH.exists()

# API Configuration
API_HOST = os.getenv('API_HOST', '0.0.0.0')
API_PORT = int(os.getenv('API_PORT', 8000))
API_RELOAD = os.getenv('API_RELOAD', 'true').lower() == 'true'

# Frontend path
FRONTEND_DIR = ROOT.parent / 'frontend' / 'public'
"""Configuration module for ForensicX backend"""
from pathlib import Path
import os

# Load .env file if present (for local development)
try:
    from dotenv import load_dotenv
    _env_file = Path(__file__).resolve().parent.parent.parent / '.env'
    if _env_file.exists():
        load_dotenv(_env_file)
        print(f"✅ Loaded .env from: {_env_file}")
    else:
        # Also try loading from the backend dir
        _env_file_backend = Path(__file__).resolve().parent.parent / '.env'
        if _env_file_backend.exists():
            load_dotenv(_env_file_backend)
            print(f"✅ Loaded .env from: {_env_file_backend}")
except ImportError:
    pass  # python-dotenv not installed yet (first run)

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

# ============================================================================
# HuggingFace LLM Configuration (remote API — no local model required)
# ============================================================================
HF_TOKEN = os.getenv('HF_TOKEN', '').strip()
HF_MODEL = os.getenv('HF_MODEL', 'deepseek-ai/DeepSeek-R1')

# LLM is enabled when a HuggingFace API token is provided
USE_LLM = bool(HF_TOKEN)

if USE_LLM:
    print(f"✅ HuggingFace LLM enabled: {HF_MODEL}")
else:
    print("⚠️  HF_TOKEN not set — running in heuristic-only mode")
    print("   Set HF_TOKEN in your .env file to enable AI-powered analysis")
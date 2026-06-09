"""Entry point for running the ForensicX backend"""
import os
import sys
import subprocess
from pathlib import Path

# Path to the virtual environment
BACKEND_DIR = Path(__file__).parent
VENV_DIR = BACKEND_DIR / "venv"
VENV_PYTHON = VENV_DIR / "bin" / "python" if os.name != 'nt' else VENV_DIR / "Scripts" / "python.exe"
REQ_FILE = BACKEND_DIR / "requirements.txt"

def setup_and_run():
    # If not running from the venv, we need to set it up and restart using the venv's Python
    if sys.prefix == sys.base_prefix or not str(sys.executable).startswith(str(VENV_DIR)):
        print("🔍 ForensicX Backend Startup (Auto-Venv)")
        print("========================================")
        
        # 1. Create venv if missing
        if not VENV_DIR.exists():
            print("📦 Creating virtual environment...")
            subprocess.check_call([sys.executable, "-m", "venv", str(VENV_DIR)])
            
        # 2. Install dependencies
        print("📥 Checking dependencies...")
        pip_exe = VENV_DIR / "bin" / "pip" if os.name != 'nt' else VENV_DIR / "Scripts" / "pip.exe"
        subprocess.check_call([str(pip_exe), "install", "-r", str(REQ_FILE), "--quiet"])
        
        # 3. Re-execute using venv Python
        print("🚀 Starting ForensicX Backend...")
        os.execv(str(VENV_PYTHON), [str(VENV_PYTHON)] + sys.argv)
        
    # --- The code below only runs if we ARE inside the venv ---
    import uvicorn
    from app.config import API_HOST, API_PORT, API_RELOAD

    # Create data directories
    for d in ['logs', 'reports', 'chats']:
        (BACKEND_DIR / "data" / d).mkdir(parents=True, exist_ok=True)

    print(f"Starting ForensicX at http://{API_HOST}:{API_PORT}")
    uvicorn.run(
        'app.main:app',
        host=API_HOST,
        port=API_PORT,
        reload=API_RELOAD
    )

if __name__ == '__main__':
    setup_and_run()
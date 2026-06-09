#!/usr/bin/env python3
"""
ForensicX Startup Wrapper
This script ensures the backend runs from the correct directory.
"""
import os
import sys
from pathlib import Path
import subprocess

if __name__ == '__main__':
    # Get the project root
    ROOT_DIR = Path(__file__).resolve().parent
    BACKEND_DIR = ROOT_DIR / "backend"
    
    # Check if backend directory exists
    if not BACKEND_DIR.exists():
        print(f"❌ Error: Backend directory not found at {BACKEND_DIR}")
        sys.exit(1)
        
    print("🚀 ForensicX Startup Wrapper")
    print(f"📁 Changing directory to: {BACKEND_DIR}")
    
    # The actual run.py is in the backend directory
    BACKEND_RUN_PY = BACKEND_DIR / "run.py"
    
    if not BACKEND_RUN_PY.exists():
        print(f"❌ Error: {BACKEND_RUN_PY} not found!")
        sys.exit(1)
        
    # Change directory so relative paths work
    os.chdir(BACKEND_DIR)
    
    # Free up port 8000 just in case
    print("🧹 Making sure port 8000 is free...")
    try:
        subprocess.run(
            "lsof -i :8000 | awk 'NR>1 {print $2}' | xargs kill -9 2>/dev/null", 
            shell=True,
            check=False
        )
    except Exception:
        pass
        
    # Execute the backend run.py
    print(f"🔄 Executing: python3 {BACKEND_RUN_PY.name}")
    os.execv(sys.executable, [sys.executable, BACKEND_RUN_PY.name])

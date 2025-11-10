#!/bin/bash
# ForensicX Backend Startup Script (macOS M2 / ARM64 compatible)

set -e

echo "🔍 ForensicX Backend Startup"
echo "=============================="

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.9+"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo "✅ Python $PYTHON_VERSION found"

# Create virtual environment if not exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Check for LLM model
if [ -f "models/Phi-3-mini-4k-instruct-q4.gguf" ]; then
    echo "✅ LLM model found - advanced insights enabled"
else
    echo "⚠️  LLM model not found - using heuristic analysis only"
    echo "   Place 'Phi-3-mini-4k-instruct-q4.gguf' in models/ directory to enable LLM"
fi

# Create data directories
mkdir -p data/{logs,reports,chats}

# Run backend
echo "🚀 Starting ForensicX Backend..."
python3 run.py
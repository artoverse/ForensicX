#!/bin/bash
# ForensicX Backend Startup Script

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

# Check for .env file
ENV_FILE="../.env"
if [ -f "$ENV_FILE" ]; then
    echo "✅ Found .env file — environment variables will be loaded"
else
    echo "⚠️  No .env file found at project root"
    echo "   To enable AI-powered analysis, create a .env file with:"
    echo "   HF_TOKEN=hf_your_token_here"
    echo "   Get a free token at: https://huggingface.co/settings/tokens"
    echo ""
fi

# Create virtual environment if not exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source venv/bin/activate

# Install/upgrade dependencies
echo "📥 Installing dependencies..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

# Create data directories
mkdir -p data/{logs,reports,chats}

# Run backend
echo ""
echo "🚀 Starting ForensicX Backend at http://localhost:8000"
echo "   Open your browser at: http://localhost:8000"
echo ""
python3 run.py
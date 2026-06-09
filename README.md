# ForensicX — Digital Forensic Analysis System

A production-ready digital forensic analyzer that processes security logs and detects anomalies using heuristics and optional AI analysis powered by **HuggingFace hosted LLM** (no local model required).

## Features

| Feature | Description |
|---------|-------------|
| 📋 **Log Analysis** | Process process, network flow, DNS, and red-team logs |
| 🔍 **Anomaly Detection** | 9-layer heuristic engine detects 30+ threat types |
| 🤖 **AI Analysis** | HuggingFace-powered deep analysis via Mistral-7B (free) |
| 💬 **Q&A Chat** | Ask questions about findings in natural language |
| 📊 **Dashboard** | Real-time visualization of incidents and IOCs |
| 📄 **PDF Reports** | Professional incident reports with charts |
| 🌐 **No Local GPU** | LLM runs remotely — works on any machine |

---

## Quick Start

### Prerequisites
- Python 3.9+
- A free [HuggingFace account](https://huggingface.co/join) (for AI analysis)

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/ForensicX.git
cd ForensicX
```

### 2. Set Up HuggingFace Token (for AI-powered analysis)

1. Go to [https://huggingface.co/settings/tokens](https://huggingface.co/settings/tokens)
2. Click **"New token"** → select **"Read"** → copy the token
3. Create a `.env` file in the project root:

```bash
cp .env.example .env
# Edit .env and paste your token:
# HF_TOKEN=hf_your_token_here
```

> ⚠️ The `.env` file is in `.gitignore` — it will **never** be committed to GitHub.

### 3. Start the Backend

```bash
chmod +x backend/run_backend.sh
./backend/run_backend.sh
```

The script will:
1. Create a Python virtual environment
2. Install all dependencies
3. Start the server at **http://localhost:8000**

### 4. Use the App

1. Open **http://localhost:8000** in your browser
2. Drag-and-drop a log file (or click to upload)
3. Click **"Run Analysis"**
4. View results in **Dashboard**, **Report**, **Graphs**, or **Q&A** tabs
5. Download the PDF report

---

## Log Format Support

### Process Logs (CSV)
```
timestamp, process_id, process_name, flag
2025-11-01 10:30:45, 1234, notepad.exe, start
```

### Network Flow Logs (CSV)
```
src_ip, duration, dst_ip, dst_port, bytes_out, bytes_in
192.168.1.100, 5.2, 203.0.113.1, 443, 1024, 2048
```

### DNS Logs (CSV)
```
timestamp, query_type, domain, response
2025-11-01 10:30:45, A, malicious.xyz, 192.0.2.1
```

---

## AI Analysis (HuggingFace)

ForensicX uses the **HuggingFace Inference API** (free tier) with:

> **`mistralai/Mistral-7B-Instruct-v0.3`**

- ✅ **Free** — requires only a free HuggingFace account
- ✅ **No GPU** — runs on HuggingFace's servers
- ✅ **No download** — no 4GB model file needed
- ✅ **Fallback** — if token is absent, heuristic analysis still works

### Without AI (heuristic mode)
The system still detects threats using a 9-layer heuristic engine covering:
brute force, privilege escalation, malware signatures, port scanning, lateral movement, data exfiltration, SQL injection, APT indicators, and more.

---

## Project Structure

```
ForensicX/
├── .env.example          # Template for environment variables
├── .gitignore
├── render.yaml           # Render.com deployment config
├── README.md
├── backend/
│   ├── app/
│   │   ├── main.py       # FastAPI routes
│   │   ├── analyzer.py   # 9-layer heuristic engine
│   │   ├── chat_manager.py # Q&A chat logic
│   │   ├── visualizer.py # Charts & PDF generation
│   │   ├── llm_service.py # HuggingFace LLM integration
│   │   ├── config.py     # Configuration & env vars
│   │   └── utils.py      # File & data utilities
│   ├── data/             # Runtime data (gitignored)
│   │   ├── logs/         # Uploaded log files
│   │   ├── reports/      # Generated PDFs & charts
│   │   └── chats/        # Chat histories
│   ├── requirements.txt
│   ├── run.py
│   └── run_backend.sh    # Startup script
└── frontend/
    └── public/
        ├── index.html    # Dashboard UI
        └── app.js        # Frontend logic
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/api/status` | System statistics |
| `POST` | `/api/upload` | Upload & analyze log file |
| `GET` | `/api/analyses` | List all analyses |
| `GET` | `/api/analysis/{id}` | Get specific analysis |
| `POST` | `/api/chat/{id}` | Q&A about an analysis |
| `GET` | `/api/chat/{id}/history` | Get chat history |
| `POST` | `/api/report/pdf/{id}` | Generate PDF report |
| `GET` | `/api/chart/{type}/{id}` | Get chart image |

---

## Deploy to Render (Free Cloud Hosting)

1. Push to GitHub
2. Create a new **Web Service** at [render.com](https://render.com)
3. Connect your repository
4. Render will auto-detect `render.yaml`
5. In the Render dashboard → **Environment** → add `HF_TOKEN` as a secret

---

## Troubleshooting

**Port 8000 already in use?**
```bash
lsof -i :8000
kill -9 <PID>
```

**Virtual environment issues?**
```bash
rm -rf backend/venv
./backend/run_backend.sh
```

**AI analysis not working?**
- Check your `.env` file has `HF_TOKEN=hf_...`
- Verify the token is valid at https://huggingface.co/settings/tokens
- The system will fall back to heuristic analysis if the token is missing/invalid

**HuggingFace rate limit?**
- Free tier allows ~30 requests/minute
- The system retries automatically once on rate limit
- For heavy use, consider [HuggingFace PRO](https://huggingface.co/pricing)

---

## License

MIT License

---

**Version:** 2.0.0  
**Updated:** 2026-06-09  
**Python:** 3.9–3.12  
**LLM:** HuggingFace Inference API (mistralai/Mistral-7B-Instruct-v0.3)

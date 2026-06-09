# ForensicX — AI-Powered Digital Forensic Analysis System

> A final-year project I built for my Computer Science degree. It analyses security logs using a combination of heuristic rule-based detection and a hosted LLM (Mistral-7B via HuggingFace). No local GPU needed.
> Deployed URL : https://forensicx-9g3u.onrender.com
---

## What it does

You upload a log file (process logs, network flows, DNS logs etc.), and the system:

1. Runs it through a 9-layer heuristic engine that checks for things like brute-force attempts, privilege escalation, lateral movement, malware signatures, SQL injection, data exfiltration patterns and more
2. Optionally uses Mistral-7B (via the free HuggingFace Inference API) for a deeper AI-generated summary
3. Shows everything in a dashboard — charts, an IOC table, incident severity breakdown
4. Lets you ask natural-language questions about the findings through a Q&A chat
5. Exports a PDF report

---

## Screenshots

> The dashboard after uploading a log file with several detected incidents.

---

## Tech stack

| Part | What I used |
|------|-------------|
| Backend | Python · FastAPI · Uvicorn |
| LLM | HuggingFace Inference API (Mistral-7B-Instruct-v0.3) — free, no local GPU |
| Analysis | Custom heuristic engine (9 layers, 30+ threat patterns) |
| PDF reports | ReportLab |
| Charts | Chart.js 4 |
| Frontend | Vanilla HTML / CSS / JavaScript |
| Deployment | Render.com (free tier) |

---

## Setup

### Requirements
- Python 3.9+
- A free HuggingFace account (for AI-powered summaries — the app still works without it)

### 1. Clone

```bash
git clone https://github.com/artoverse/ForensicX.git
cd ForensicX
```

### 2. Get a HuggingFace token (optional but recommended)

Go to [https://huggingface.co/settings/tokens](https://huggingface.co/settings/tokens), create a token (Read access is enough), then:

```bash
cp .env.example .env
# Open .env and paste your token:
# HF_TOKEN=hf_xxxxxxxxxxxxxxxxx
```

If you skip this, the app still works — it just uses the heuristic engine only and skips the AI summary.

### 3. Start the server

```bash
chmod +x backend/run_backend.sh
./backend/run_backend.sh
```

This creates a virtual environment, installs dependencies, and starts the server at **http://localhost:8000**. Open that in your browser.

---

## Log file format

The system accepts plain text / CSV logs. Some examples of what it can parse:

**Process logs:**
```
2025-11-01 10:30:45, 1234, powershell.exe, start
2025-11-01 10:31:00, 5678, mimikatz.exe, start
```

**Network logs:**
```
src_ip, duration, dst_ip, dst_port, bytes_out, bytes_in
192.168.1.10, 3.2, 203.0.113.5, 4444, 102400, 512
```

**DNS logs:**
```
timestamp, query_type, domain, response
2025-11-01 10:32:00, A, malicious-c2.xyz, 192.0.2.1
```

---

## How the heuristic detection works

I built a 9-layer pipeline that processes the log line by line:

| Layer | What it checks |
|-------|----------------|
| 1 | Pattern matching — known malware names, tools (mimikatz, netcat, etc.) |
| 2 | Behavioural patterns — process chains, parent-child relationships |
| 3 | Network anomalies — port scanning, unusual destinations, high byte counts |
| 4 | Auth failures — brute-force thresholds, repeated failed logins |
| 5 | Privilege escalation — sudo abuse, UAC bypass patterns |
| 6 | Data exfiltration — large outbound transfers, suspicious timing |
| 7 | Malware indicators — file extensions, obfuscated commands |
| 8 | APT patterns — multi-stage attack sequences |
| 9 | IOC extraction — IPs, domains, hashes |

Each incident gets a severity (Critical / High / Medium / Low) and a detail message.

---

## API endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/upload` | Upload & analyse a log file |
| GET | `/api/analyses` | List all past analyses |
| GET | `/api/analysis/{id}` | Get one analysis by ID |
| POST | `/api/chat/{id}` | Ask a question about an analysis |
| GET | `/api/chat/{id}/history` | Get chat history |
| POST | `/api/report/pdf/{id}` | Generate PDF report |

Interactive docs are at `http://localhost:8000/docs` (Swagger UI).

---

## Project structure

```
ForensicX/
├── .env.example
├── .gitignore
├── render.yaml
├── README.md
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI routes
│   │   ├── analyzer.py      # heuristic detection engine
│   │   ├── llm_service.py   # HuggingFace API integration
│   │   ├── chat_manager.py  # Q&A logic
│   │   ├── visualizer.py    # charts + PDF
│   │   ├── config.py        # env vars, paths
│   │   └── utils.py
│   ├── requirements.txt
│   ├── run.py
│   └── run_backend.sh
└── frontend/
    └── public/
        ├── index.html
        └── app.js
```

---

## Deployment (Render.com)

The `render.yaml` is already configured. Just:

1. Push to GitHub
2. Create a new Web Service on [render.com](https://render.com) and connect the repo
3. Add your `HF_TOKEN` as a secret environment variable in the Render dashboard

---

## Known limitations

- Free HuggingFace tier has rate limits (~30 requests/minute). If you hit them, the system waits and retries once automatically, then falls back to heuristic-only mode.
- The heuristic engine is rule-based, so it won't catch novel/unknown threats unless I add more patterns.
- PDF generation is basic — it works, but it's not production-quality styled.

---

## What I learned building this

- FastAPI + Starlette for serving both API endpoints and a static frontend from one server
- How to use the HuggingFace Inference API (much easier than running models locally)
- Building a multi-layer text analysis pipeline from scratch
- PDF generation with ReportLab (way more work than I expected)

---

*Built as a final-year Computer Science project · 2025*

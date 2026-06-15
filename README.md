# BountyOS — Autonomous Bug Bounty Platform

Full-stack, AI-powered bug bounty automation framework.
FastAPI backend + React dashboard + Gemini/Vertex-powered agents.

---

## Architecture

```
bountyos/
├── api/
│   ├── main.py              # FastAPI app (serves dashboard + API)
│   ├── database.py          # SQLModel engine (SQLite → Postgres-ready)
│   ├── models.py            # ORM models: Target, Scan, Finding, Approval
│   ├── agents/
│   │   ├── coordinator.py   # AI Coordinator (campaign-level reasoning)
│   │   └── exploit_agent.py # Exploit Agent (technique-level execution)
│   ├── tools/
│   │   └── __init__.py      # Tool registry: subfinder, nmap, nuclei, sqlmap, ffuf...
│   └── routes/
│       ├── targets.py       # Target CRUD
│       ├── scans.py         # Scan orchestration + background runner
│       ├── findings.py      # Findings + Approvals
│       ├── ai.py            # AI chat + manual analysis trigger
│       └── ws.py            # WebSocket live event stream
├── dashboard/               # React + Vite source
├── static/                  # Built React app (served by FastAPI)
└── requirements.txt
```

---

## Agent Pipeline

```
Target defined
    ↓
Recon Phase      subfinder → nmap → whatweb → httpx
    ↓
VulnScan Phase   headers → nuclei → ffuf → sqlmap
    ↓
AI Coordinator   Reads all findings, reasons over attack surface,
                 builds exploit chain step by step
    ↓ (for each step)
    ├─ Safe step      → Exploit Agent executes immediately
    └─ Destructive    → Approval gate → operator approves/rejects
                                ↓ (if approved)
                        Exploit Agent: generate payloads → execute → validate
                        Up to 3 retry attempts with variation
                        Confirmed findings → persisted to DB with CWE + remediation
    ↓
Finished — findings table + AI summary available
```

---

## Setup

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 2. Install external tools (Kali / Parrot recommended)

```bash
# Recon
apt install nmap whatweb -y
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# VulnScan
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest
apt install sqlmap -y
```

### 3. Set API key

```bash
# For Gemini Developer API
export GEMINI_API_KEY=your_gemini_api_key_here

# Or for Vertex AI (recommended):
export GOOGLE_API_KEY=...
export GOOGLE_CLOUD_PROJECT=your-project-id
export GOOGLE_CLOUD_LOCATION=global
export GOOGLE_GENAI_USE_VERTEXAI=true
```

### 4. Run

```bash
uvicorn api.main:app --reload --port 8000
```

Dashboard: http://localhost:8000  
API docs:  http://localhost:8000/docs

---

## Collaborative Debate Engine

BountyOS includes an optional Collaborative Debate Engine that performs an internal
multi-agent review (Skeptic, Proponent, Verdict) on high/critical findings before
they are finalized. It is Gemini/Vertex compatible and disabled by default.

Highlights:
- Reviews only high/critical findings by default
- SkepticAgent challenges evidence
- ProponentAgent defends using only existing evidence
- VerdictAgent returns one of: CONFIRMED, DOWNGRADED, REJECTED, NEEDS_EVIDENCE
- Safety: the debate engine treats evidence as untrusted and never executes tools

Environment variables:

```bash
export BOUNTYOS_DEBATE_ENABLED=false
export BOUNTYOS_DEBATE_MODEL=gemini-2.5-flash
export BOUNTYOS_DEBATE_TIMEOUT_SECONDS=60
export BOUNTYOS_DEBATE_MAX_TOKENS=1500
```

API examples:

```bash
curl -X POST http://localhost:8000/api/v1/debate/findings/FINDING_ID/run
curl -X POST http://localhost:8000/api/v1/debate/scans/SCAN_ID/run
curl http://localhost:8000/api/v1/debate/records/FINDING_ID
```

---

## Model routing

Environment variables:

```bash
export BOUNTYOS_LOCAL_MODEL="heuristic-local"
export BOUNTYOS_LIGHT_MODEL="heuristic-light"
export BOUNTYOS_MAIN_PROVIDER="vertex"
export BOUNTYOS_MAIN_MODEL="gemini-2.5-flash"
export BOUNTYOS_EXPLOIT_MODEL="gemini-2.5-pro"
```

Routing:

- `local_recon_expert` handles recon/status/dashboard commands.
- `light_triage_expert` handles simple chat and command parsing.
- `bug_reasoning_expert` handles post-scan bug/finding analysis.
- `exploit_validation_expert` handles approved active validation reasoning.

This upgrade does not add a new stricter scope validator or replace existing tool behavior.

---

## Bounty Program Radar

This build adds a passive Program Radar for online/public bug bounty program discovery.

... (rest of README unchanged)

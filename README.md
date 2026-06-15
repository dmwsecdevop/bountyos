# BountyOS — Autonomous Bug Bounty Platform

Full-stack, AI-powered bug bounty automation framework.
FastAPI backend + React dashboard + dual Claude-powered agents.

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
export ANTHROPIC_API_KEY=sk-ant-...
```

### 4. Run

```bash
uvicorn api.main:app --reload --port 8000
```

Dashboard: http://localhost:8000  
API docs:  http://localhost:8000/docs

---

## Dashboard Pages

| Page       | Description |
|------------|-------------|
| Targets    | Manage bug bounty programs, define scope, launch scans |
| Scans      | View all scans, live status, cancel running scans |
| Scan Detail| Live WebSocket console, findings by phase, AI summary |
| Findings   | Global findings table, severity filter, false-positive flagging |
| Approvals  | Human-in-the-loop gate for destructive exploit steps |
| AI Chat    | Context-aware Q&A with scan injection |

---

## API Reference

### Targets
```
GET    /api/v1/targets/
POST   /api/v1/targets/
PATCH  /api/v1/targets/{id}
DELETE /api/v1/targets/{id}
```

### Scans
```
POST   /api/v1/scans/              # { target_id, config }
GET    /api/v1/scans/{id}/events   # event log
GET    /api/v1/scans/{id}/findings
POST   /api/v1/scans/{id}/cancel
WS     /ws/scans/{id}             # live stream
```

### Scan Config Options
```json
{
  "recon_tools":       ["subfinder", "nmap", "whatweb", "httpx"],
  "vulnscan_tools":    ["headers", "nuclei", "ffuf", "sqlmap"],
  "skip_ai":           false,
  "ai_max_iterations": 20
}
```

### AI
```
POST  /api/v1/ai/chat                 # { scan_id?, messages }
POST  /api/v1/ai/analyze/{scan_id}    # manually trigger coordinator
GET   /api/v1/ai/scan/{scan_id}/summary
```

### Approvals
```
GET   /api/v1/approvals/pending
POST  /api/v1/approvals/{id}/decide   # { status: "approved"|"rejected" }
```

---

## Adding a New Tool

Create a subclass of `BaseTool` in `api/tools/__init__.py`:

```python
class MyTool(BaseTool):
    name  = "mytool"
    phase = "vulnscan"   # or "recon"

    async def run(self, scan_id: str, target: str, **kwargs):
        yield self.event(scan_id, f"Starting on {target}")
        async for ev in self._run_subprocess(f"mytool {target}", scan_id):
            yield ev
        yield self.event(scan_id, "Done")

# Register it
VULNSCAN_TOOLS["mytool"] = MyTool()
```

---

## Environment Variables

| Variable           | Default             | Description |
|--------------------|---------------------|-------------|
| ANTHROPIC_API_KEY  | required            | Used by Coordinator + Exploit Agent + AI Chat |
| DATABASE_URL       | sqlite:///./bountyos.db | Swap to `postgresql://...` for production |

---

## Narrow Upgrade: Realtime + Architect Chat Agent + Mixture of Experts

This build keeps the original BountyOS behavior and adds only the requested command-center layer:

- Realtime Live dashboard page at `/live`
- Global live WebSocket at `/ws/live`
- Snapshot API at `/api/v1/live/snapshot`
- Architect Agent command runner: Observe → Reason → Think → Act
- Chat commands can run existing BountyOS actions
- Mixture-of-Models/Experts router for workload-based routing

### Architect Agent commands

Examples:

```bash
curl -X POST http://localhost:8000/api/v1/agent/command \
  -H 'Content-Type: application/json' \
  -d '{"transcript":"show targets"}'
```

```bash
curl -X POST http://localhost:8000/api/v1/agent/command \
  -H 'Content-Type: application/json' \
  -d '{"transcript":"run passive recon","selected_target_id":"TARGET_ID"}'
```

```bash
curl -X POST http://localhost:8000/api/v1/agent/command \
  -H 'Content-Type: application/json' \
  -d '{"transcript":"run aggressive scan","selected_target_id":"TARGET_ID","approve":true}'
```

### Model routing

Environment variables:

```bash
export BOUNTYOS_LOCAL_MODEL="heuristic-local"
export BOUNTYOS_LIGHT_MODEL="heuristic-light"
export BOUNTYOS_MAIN_PROVIDER="anthropic"
export BOUNTYOS_MAIN_MODEL="claude-opus-4-5"
export BOUNTYOS_EXPLOIT_MODEL="claude-opus-4-5"
```

Routing:

- `local_recon_expert` handles recon/status/dashboard commands.
- `light_triage_expert` handles simple chat and command parsing.
- `bug_reasoning_expert` handles post-scan bug/finding analysis.
- `exploit_validation_expert` handles approved active validation reasoning.

This upgrade does not add a new stricter scope validator or replace existing tool behavior.

## Bounty Program Radar

This build adds a passive Program Radar for online/public bug bounty program discovery.

What it does:

- Checks JSON bug bounty program feeds
- Uses ProjectDiscovery public bug bounty programs feed by default
- Tracks new and changed programs
- Stores domains/scope roots in the BountyOS database
- Imports program domains as BountyOS targets on demand
- Streams program events into `/ws/live`
- Lets the Architect chat agent run commands such as `check programs`, `show programs`, and `add program targets`

It does not start aggressive testing by itself.

### Endpoints

```bash
curl http://localhost:8000/api/v1/programs/sources
curl http://localhost:8000/api/v1/programs/snapshot
curl http://localhost:8000/api/v1/programs/

curl -X POST http://localhost:8000/api/v1/programs/check \
  -H 'Content-Type: application/json' \
  -d '{"max_programs":500}'

curl -X POST http://localhost:8000/api/v1/programs/<PROGRAM_ID>/add-targets \
  -H 'Content-Type: application/json' \
  -d '{"limit":25}'
```

### Chat agent commands

```txt
check programs
show programs
add program targets
check online bug bounty programs
```

### Custom program feeds

Set comma-separated JSON feed URLs:

```bash
export BOUNTYOS_PROGRAM_FEEDS="https://example.com/programs.json,https://example.com/private-invites.json"
```

Supported feed shapes:

```json
[
  {"name":"Example Program","url":"https://example.com/security","bounty":true,"domains":["example.com","api.example.com"]}
]
```

or:

```json
{"programs":[{"name":"Example Program","offers_bounty":true,"domains":["example.com"]}]}
```

## Live Data + Voice Chat Upgrade

BountyOS now routes random/current questions through a lightweight Live Data Expert instead of letting the main model guess.

New endpoints:

```bash
curl http://localhost:8000/api/v1/live-data/capabilities
curl -X POST http://localhost:8000/api/v1/live-data/query \
  -H 'Content-Type: application/json' \
  -d '{"query":"what is today us dollar rate"}'
```

Supported live-data questions:

- USD/currency exchange rates, for example `what is today us dollar rate`
- BTC/ETH prices
- Recent CVEs from NVD
- Public IP lookup

The Architect Agent and AI Chat both use the same Mixture-of-Models routing:

- `local_recon_expert` for recon/status/program commands
- `light_triage_expert` for simple chat
- `live_data_expert` for current data lookups
- `bug_reasoning_expert` for scan/finding reasoning
- `exploit_validation_expert` for approved active validation planning

Voice input is browser-side Web Speech API. Audio is not sent to the backend; only the transcript is sent as a normal chat/agent command.

---

## Bounty Account Hub 🔐

This upgrade adds **Connected Bounty Accounts** for HackerOne, Bugcrowd, Intigriti, YesWeHack, and custom JSON/API feeds.

Use it for account-connected program discovery:

- Sync public/private/invited programs where your platform API permissions allow it
- Import visible program scope into Program Radar
- Show connected programs on the LIVE dashboard
- Let the Architect Agent run account-sync commands

BountyOS stores API/OAuth tokens locally encrypted using `BOUNTYOS_ACCOUNT_SECRET` or `BOUNTYOS_ACCOUNT_KEY`.
It does **not** store raw platform passwords.

### Routes

```bash
curl http://localhost:8000/api/v1/accounts/capabilities
curl http://localhost:8000/api/v1/accounts/snapshot
curl http://localhost:8000/api/v1/accounts/
```

Create an account connector:

```bash
curl -X POST http://localhost:8000/api/v1/accounts/ \
  -H "Content-Type: application/json" \
  -d '{
    "platform":"hackerone",
    "display_name":"My HackerOne",
    "username":"YOUR_TOKEN_IDENTIFIER",
    "token_secret":"YOUR_API_TOKEN",
    "auth_type":"basic_token"
  }'
```

Sync one account:

```bash
curl -X POST http://localhost:8000/api/v1/accounts/<ACCOUNT_ID>/sync \
  -H "Content-Type: application/json" \
  -d '{"max_items":200}'
```

Sync all connected bounty accounts:

```bash
curl -X POST http://localhost:8000/api/v1/accounts/sync-all \
  -H "Content-Type: application/json" \
  -d '{"max_items":200}'
```

### Agent commands

```txt
sync bounty accounts
check my bugcrowd programs
check my hackerone programs
show bounty accounts
show private invites
add program targets
```

### Notes

Platform API coverage depends on your account permissions and the platform endpoint available to you.
If a platform blocks a path or requires a different API route, use a custom `api_base_url` and optional notes format:

```txt
paths=/v1/programs,/v1/invites
```

This upgrade is intentionally narrow: it adds connected account sync and UI, but does not change scanner safety, scope validation, or auth behavior.


## Animated Opportunity Upgrade

This build adds:

- Program Opportunity Scorer (`/api/v1/programs/opportunities`)
- Easy/high-upside program recommendations (`/api/v1/programs/recommend-easy`)
- Expanded program intelligence (`/api/v1/programs/{program_id}/opportunity`)
- Chat commands such as `find easy scope program`, `best HackerOne program`, `less effort more money target`
- Animated landscape dashboard layer with a roaming bug and bug catcher

Opportunity scores are prioritization estimates only. They do not guarantee a bounty or a bug.


## Connector resilience and error handling

BountyOS now classifies outbound API failures instead of returning raw provider errors:

- `token_expired_or_invalid` for HTTP 401
- `access_denied` for HTTP 403
- `rate_limited` for HTTP 429, respecting `Retry-After` where available
- `service_unavailable` for HTTP 5xx/408/425
- `network_timeout` and `network_error` for connectivity failures
- `endpoint_not_found` and `invalid_json` for configuration/provider response problems

Rate limits and temporary outages are retried with exponential backoff. Existing synced programs are preserved when a provider is unavailable. Connector health is available at:

```bash
curl http://localhost:8000/api/v1/connector-health/
```

Optional environment variables:

```bash
export BOUNTYOS_CONNECTOR_RETRIES=3
export BOUNTYOS_RETRY_BASE_SECONDS=0.75
export BOUNTYOS_MAX_RETRY_WAIT=8
```

---

## BountyOS v5 — Full Hacker Mindset / Hunter Workflow

The **HUNTER** workspace connects the previously separate modules into one lifecycle:

```text
Observe → Attack Graph → Bug Hypotheses → Adaptive Plan
        → Approval → Controlled Validation → Evidence
        → Bounty Report → Experience Learning
```

### New backend modules

```text
api/intelligence/attack_graph.py
api/intelligence/memory.py
api/intelligence/hypothesis_engine.py
api/intelligence/adaptive_planner.py
api/validation/policy.py
api/validation/evidence.py
api/validation/engine.py
api/reporting/report_agent.py
api/learning/experience_store.py
api/labs/digital_twin.py
api/routes/hunter.py
```

### New dashboard

Open **HUNTER** in the sidebar (`/hunter`). It includes:

- animated eight-stage hunter lifecycle
- attack-surface knowledge graph
- evidence-backed Bug Hunter Brain hypotheses
- expected-value next-action planner
- approval-gated validation cards
- redacted SHA-256 evidence records
- report quality scoring and Markdown/JSON/HTML exports
- shared agent memory and experience utility history
- synthetic digital-twin labs for SaaS/API, exposure and agentic-support scenarios

### Main API

```bash
# Run the complete workflow for a scan
curl -X POST http://localhost:8000/api/v1/hunter/scans/SCAN_ID/run \
  -H 'Content-Type: application/json' \
  -d '{}'

# Load the complete Hunter snapshot
curl http://localhost:8000/api/v1/hunter/scans/SCAN_ID/snapshot

# Prepare a planner action for controlled validation
curl -X POST http://localhost:8000/api/v1/hunter/validations \
  -H 'Content-Type: application/json' \
  -d '{"decision_id":"DECISION_ID"}'

# Approve a validation attempt
curl -X POST http://localhost:8000/api/v1/hunter/validations/ATTEMPT_ID/approval \
  -H 'Content-Type: application/json' \
  -d '{"approved":true}'

# Run the controlled validation in dry-run mode
curl -X POST http://localhost:8000/api/v1/hunter/validations/ATTEMPT_ID/execute \
  -H 'Content-Type: application/json' \
  -d '{"dry_run":true}'

# Generate a bounty-ready report
curl -X POST http://localhost:8000/api/v1/hunter/scans/SCAN_ID/reports \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### Chat commands

The Architect Agent understands commands including:

```text
run full hunter workflow
show attack graph
show bug hypotheses
generate bounty report
```

### Automatic post-processing

Completed passive and aggressive scans automatically run the Hunter graph,
hypothesis and planner stages unless the scan config contains:

```json
{"skip_hunter": true}
```

A draft report is generated automatically when scan findings exist unless:

```json
{"auto_report": false}
```

### Controlled validation design

The Hunter validation engine does not execute arbitrary model-generated shell
commands. Safe evidence analysis runs directly. Active validation creates an
approval request and a bounded plan with a request budget and stop condition.
Dry-run is the default.

## Agent Quality Loop (v5.1)

BountyOS now evaluates its own Hunter outputs against stored evidence rather than trusting agent prose.

Quality lifecycle:

```text
Agent output
→ deterministic critic
→ evidence verifier
→ confidence calibration
→ accept / warn / retry / reject
→ controlled retry or escalation
→ performance record
```

The evaluator scores evidence quality, accuracy, reproducibility, impact confidence, efficiency, and safety. It evaluates hypotheses, adaptive plans, validation results, and reports. Active validation is never retried or executed automatically; a retry only prepares a revised approval-gated attempt.

API examples:

```bash
curl -X POST http://localhost:8000/api/v1/quality/scans/SCAN_ID/evaluate \
  -H 'Content-Type: application/json' \
  -d '{}'

curl http://localhost:8000/api/v1/quality/scans/SCAN_ID
curl http://localhost:8000/api/v1/quality/performance
curl -X POST http://localhost:8000/api/v1/quality/evaluations/EVALUATION_ID/retry
```

Chat commands include `evaluate agent work`, `show quality scores`, `show model performance`, and `retry weak work`.

## v5.2 Gemini Hybrid Runner

BountyOS can now execute tools in three locations:

- **Local** — Cloud Run container tools.
- **Remote** — a connected Parrot OS or GCP worker runner.
- **Hybrid** — prefer remote tools and fall back to Cloud Run.

Open **RUNNERS** in the dashboard to create a runner token, choose the execution mode, inspect the real remote inventory, and review tool-job evidence. The Linux runner authenticates inside the encrypted WebSocket rather than placing its token in the URL.

See `RUNNER_BRIDGE_GUIDE.md` for deployment and Parrot/worker setup.

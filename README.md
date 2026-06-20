# BountyOS v6.0.0 — Self-Hosted Bug Bounty Command Center

BountyOS v6 is a personal, self-hosted, AI-assisted bug bounty operations platform. It combines a FastAPI backend, React dashboard, Gemini Hunter Brain, authenticated runner bridge, targets/scans/findings, live logs, integrations, reports, and quality agents.

The current design goal is simple: **Codex-style command UI first, raw logs only when opened, integrations/tools on separate pages.**

## Current dashboard layout

BountyOS now uses a cleaner multi-page console:

- **Hunter Brain** — main chat/command panel. Natural language summaries only. Raw JSON/logs stay collapsed.
- **Findings** — parsed finding cards and evidence summaries.
- **Integrations** — API/setup boxes for Gemini, Chrome DevTools MCP, Caido, Burp, ZAP, HackerOne, and Bugcrowd.
- **Tools** — runner inventory and tool versions.
- **Settings** — safety and local-use notes.

The main chat should not dump large JSON blocks. Use **Raw JSON**, **Planner details**, **Evidence**, or **Show Logs** only when you need low-level output.

## What BountyOS v6 includes

- FastAPI API and static React dashboard served from one app container
- Gemini/Gemini API model routing and optional Vertex AI mode
- Gemini 3.5 Flash routing for agentic/browser/proxy analysis where configured
- Authenticated outbound runner bridge for WSL, VM, VPS, or container tools
- WebSocket routes for live scan and runner events
- Targets, scans, findings, approvals, reports, and quality review agents
- Hunter Brain UI, knowledge graph, and program radar workflows
- Postgres-backed self-host deployment with Redis cache service

## Quick self-host install

```bash
git clone https://github.com/dmwsecdevop/bountyos.git
cd bountyos
cp .env.example .env
nano .env
./install.sh
```

Then open:

```text
http://localhost:8080
```

For production VPS setup, Nginx, TLS, runner setup, updates, and backup/restore, see [`SELF_HOST_DEPLOYMENT.md`](SELF_HOST_DEPLOYMENT.md).

## Required Gemini API configuration

Set these values in `.env` for the default self-host mode. BountyOS v6 uses performance-first routing: Flash-class models handle fast planning/browser/proxy work, while Pro-class models handle validation, high-impact reasoning, severity review, and report writing.

```bash
BOUNTYOS_VERSION=6.0.0
BOUNTYOS_EXECUTION_MODE=hybrid
BOUNTYOS_AI_PROVIDER=gemini
BOUNTYOS_MAIN_PROVIDER=gemini
GOOGLE_GENAI_USE_VERTEXAI=false
GEMINI_API_KEY=PASTE_GEMINI_API_KEY
BOUNTYOS_MODEL_POLICY=performance
BOUNTYOS_CHAT_MODEL=gemini-2.5-flash-lite
BOUNTYOS_RECON_MODEL=gemini-2.5-flash
BOUNTYOS_PLANNER_MODEL=gemini-2.5-flash
BOUNTYOS_PARSER_MODEL=gemini-2.5-flash
BOUNTYOS_AGENTIC_MODEL=gemini-3.5-flash
BOUNTYOS_BROWSER_MODEL=gemini-3.5-flash
BOUNTYOS_CAIDO_MODEL=gemini-3.5-flash
BOUNTYOS_EXPLOIT_MODEL=gemini-2.5-pro
BOUNTYOS_VALIDATION_MODEL=gemini-2.5-pro
BOUNTYOS_BUG_FALLBACK_MODEL=gemini-3.5-flash
BOUNTYOS_REPORT_MODEL=gemini-2.5-pro
```

## Local Docker workflow

```bash
cd ~/bountyos
git pull
docker compose down
docker compose build --no-cache
docker compose up -d
docker compose ps
curl -s http://localhost:8080/health | python3 -m json.tool
```

Open:

```text
http://localhost:8080
```

## Local runner workflow

Heavy recon tools should run through the runner, not inside the app container.

```bash
cd ~/bountyos
source .runner-venv/bin/activate
./start-bountyos.sh
curl -s http://localhost:8080/api/v1/runners/capabilities | python3 -m json.tool
```

Expected: `online` contains `bountyos-local-runner` and a non-zero tool count.

Known WSL/tool cleanup targets:

- If the runner reports Python `httpx` instead of ProjectDiscovery `httpx`, fix PATH/tool discovery.
- `whatweb`, `dnsrecon`, `dirsearch`, and some Impacket helpers may need package repair on Ubuntu/WSL.
- Broken tools should be fixed in install scripts and runner discovery, not hidden in the UI.

## Browser MCP and Caido integrations

Optional integrations are disabled until configured. They never navigate outside approved target scope, and active/intrusive validation remains approval-gated.

```bash
# Chrome DevTools MCP / browser evidence
export CHROME_DEVTOOLS_MCP_URL=http://127.0.0.1:9222
curl http://localhost:8080/api/v1/integrations/browser/status
curl -X POST http://localhost:8080/api/v1/integrations/browser/analyze \
  -H 'Content-Type: application/json' \
  -d '{"target_id":"TARGET_UUID","scan_id":"SCAN_UUID"}'

# Caido proxy traffic import/analysis
export CAIDO_URL=http://127.0.0.1:8080
export CAIDO_API_TOKEN=PASTE_CAIDO_TOKEN
curl http://localhost:8080/api/v1/integrations/caido/status
curl -X POST http://localhost:8080/api/v1/integrations/caido/import-history \
  -H 'Content-Type: application/json' \
  -d '{"limit":100,"target_id":"TARGET_UUID","scan_id":"SCAN_UUID"}'
curl -X POST http://localhost:8080/api/v1/integrations/caido/analyze-request \
  -H 'Content-Type: application/json' \
  -d '{"request":{"host":"example.com","method":"GET","path":"/api/me"},"target_id":"TARGET_UUID"}'
```

Useful Hunter Brain commands:

```text
analyze browser
use browser on the selected target
check caido traffic
use caido to analyze proxy history
```

## Optional Vertex AI mode

Vertex AI remains available for operators who already run on Google Cloud. Set `GOOGLE_GENAI_USE_VERTEXAI=true`, configure `GOOGLE_CLOUD_PROJECT` and `GOOGLE_CLOUD_LOCATION`, and keep the Gemini model names above.

Cloud Run deployment is optional/legacy for this repo. If you still need it, see [`CLOUD_RUN_DEPLOYMENT.md`](CLOUD_RUN_DEPLOYMENT.md).

## Docker Compose services

The self-host stack includes:

- `bountyos` app on port `8080`
- `postgres:16` with persistent `postgres_data`
- `redis:7` with persistent `redis_data`
- `bountyos_data` for app-local runtime data

Common commands:

```bash
docker compose ps
docker compose logs -f bountyos
docker compose up -d
docker compose down
```

## Local development

Backend:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn api.main:app --reload --port 8000
```

Dashboard source:

```bash
cd dashboard
npm install
npm run build
cp -R dist/* ../static/
```

## Security notes

- Use BountyOS only for authorized targets and your own lab assets.
- Do not commit `.env`, API keys, database passwords, runner tokens, logs, SQLite databases, or backups.
- Active/destructive tooling must remain approval-gated.
- Raw logs can contain secrets; keep them collapsed by default and redact before sharing.
- Keep `BOUNTYOS_VERSION=6.0.0` for this release line.
- Configure `ALLOWED_ORIGINS` for your production domain.

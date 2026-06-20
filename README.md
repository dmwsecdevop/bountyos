# BountyOS v6.0.0 — Self-Hosted Bug Bounty Command Center

BountyOS v6 is a self-hosted, AI-assisted bug bounty operations platform. It combines a FastAPI backend, a static React v6 Command Center UI, authenticated runner bridge, WebSocket live updates, targets/scans/findings, Hunter Brain, knowledge graph, program radar, report agents, and quality agents.

The recommended deployment for v6 is a VPS-first Docker Compose stack with Postgres and Redis. Gemini API is the default AI mode, with optional Vertex AI support for operators who already use Google Cloud.

## What BountyOS v6 includes

- FastAPI API and static React dashboard served from one app container
- Gemini/Gemini API model routing and optional Vertex AI mode
- Authenticated outbound runner bridge for VM/Docker security tools
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

Set these values in `.env` for the default self-host mode. BountyOS v6 uses performance-first routing: Flash-class models handle fast planning/browser/proxy work, while Pro-class models handle exploit validation, high-impact reasoning, severity validation, and report writing.

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

## Browser MCP and Caido integrations

Optional integrations are disabled until configured. They never navigate outside approved target scope, and any active/intrusive validation remains approval-gated.

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

## Runner bridge

Heavy recon and active validation tools should run outside the app container. Create a runner in the BountyOS UI, copy the one-time runner token, then start a runner host/container with:

```bash
export SERVER=https://YOUR_DOMAIN_HERE
export RUNNER_ID=PASTE_RUNNER_ID
export RUNNER_TOKEN=PASTE_RUNNER_TOKEN
./scripts/start-runner-docker.sh
```

The runner connects outbound over the authenticated WebSocket bridge, advertises allowed tools, and executes safe argv jobs without opening inbound ports.

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

- Do not commit `.env`, API keys, database passwords, runner tokens, logs, SQLite databases, or backups.
- Active/destructive tooling must remain approval-gated.
- Keep `BOUNTYOS_VERSION=6.0.0` for this release line.
- Configure `ALLOWED_ORIGINS` for your production domain.

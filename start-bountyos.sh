#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required for start-bountyos.sh. Install Docker Desktop/Engine first." >&2
  exit 1
fi

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example. Edit GEMINI_API_KEY for AI features."
fi

docker compose up -d

HEALTH_URL="${BOUNTYOS_HEALTH_URL:-http://127.0.0.1:8080/health}"
echo "Waiting for $HEALTH_URL ..."
for _ in {1..60}; do
  if curl -fsS "$HEALTH_URL" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -fsS "$HEALTH_URL" >/dev/null

if [[ -f .runner.pid ]] && kill -0 "$(cat .runner.pid)" >/dev/null 2>&1; then
  echo "Local runner already running with PID $(cat .runner.pid)"
else
  nohup scripts/start-local-runner.sh > runner.log 2>&1 &
  echo $! > .runner.pid
  echo "Started local runner with PID $(cat .runner.pid)"
fi

sleep 2

echo "Dashboard: http://127.0.0.1:8080"
echo "Runner status:"
curl -sS http://127.0.0.1:8080/api/v1/runners/capabilities || true
echo

#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required. Install Docker Engine and the Docker Compose plugin first." >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose plugin is required. Install docker compose v2 first." >&2
  exit 1
fi

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example. Edit GEMINI_API_KEY and POSTGRES_PASSWORD before exposing the service."
fi

docker compose build
docker compose up -d

echo ""
echo "BountyOS v6 is starting at: http://localhost:8080"
echo "View logs with: docker compose logs -f bountyos"

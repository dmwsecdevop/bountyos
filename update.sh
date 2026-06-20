#!/usr/bin/env bash
set -euo pipefail

git pull --ff-only
docker compose build
docker compose up -d

docker compose logs --tail=100 bountyos

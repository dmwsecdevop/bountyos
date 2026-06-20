# BountyOS v6 Self-Hosted VPS Deployment

BountyOS v6 is designed to run cleanly on a self-hosted VPS with Docker Compose. This is the recommended deployment path for operators who do not want to depend on GCP trial infrastructure. Cloud Run remains optional/legacy for teams that already use Google Cloud.

## Recommended VPS specs

- Minimum: 4 vCPU, 8GB RAM, 100GB NVMe, Ubuntu 24.04 LTS
- Future / larger programs: 8 vCPU, 16GB RAM, 200GB NVMe

Run heavy VM/Docker security tools on a separate runner host whenever possible. The web container serves FastAPI, the static React v6 Command Center UI, WebSockets, runner bridge APIs, targets/scans/findings, Hunter Brain, knowledge graph, program radar, report agents, and quality agents.

## India payment-friendly VPS providers

Common VPS providers with India-friendly payment options include:

- Hostinger VPS
- MilesWeb VPS
- YouStable VPS

Choose Ubuntu 24.04 LTS, NVMe storage, and a plan that lets you upgrade CPU/RAM as scan volume grows.

## 1. Install Docker on Ubuntu 24.04

```bash
sudo apt update
sudo apt install -y ca-certificates curl git
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"
newgrp docker
```

Verify Docker Compose is available:

```bash
docker compose version
```

## 2. Clone and configure BountyOS

```bash
git clone https://github.com/dmwsecdevop/bountyos.git
cd bountyos
cp .env.example .env
nano .env
```

At minimum, change:

```bash
GEMINI_API_KEY=PASTE_GEMINI_API_KEY
POSTGRES_PASSWORD=bountyos_change_me
DATABASE_URL=postgresql+psycopg://bountyos:bountyos_change_me@postgres:5432/bountyos
ALLOWED_ORIGINS=https://YOUR_DOMAIN_HERE
```

Keep `BOUNTYOS_VERSION=6.0.0` for BountyOS v6.

## 3. Gemini API setup

BountyOS v6 supports Gemini API by default and optional Vertex AI. No other AI provider is required.

For Gemini API self-host mode:

```bash
BOUNTYOS_AI_PROVIDER=gemini
BOUNTYOS_MAIN_PROVIDER=gemini
GOOGLE_GENAI_USE_VERTEXAI=false
GEMINI_API_KEY=PASTE_GEMINI_API_KEY
BOUNTYOS_LIGHT_MODEL=gemini-2.5-flash-lite
BOUNTYOS_RECON_MODEL=gemini-2.5-flash
BOUNTYOS_MAIN_MODEL=gemini-2.5-pro
BOUNTYOS_AGGRESSIVE_MODEL=gemini-2.5-pro
BOUNTYOS_EXPLOIT_MODEL=gemini-2.5-pro
```

For optional Vertex AI mode, set the Google Cloud project/location values in `.env`, set `GOOGLE_GENAI_USE_VERTEXAI=true`, and keep the Gemini model routing variables.

## 4. Install with the helper script

```bash
./install.sh
```

The script checks Docker, creates `.env` from `.env.example` if needed, builds the app, starts Postgres/Redis/BountyOS, and prints the local URL.

## 5. Docker Compose commands

```bash
docker compose ps
docker compose logs -f bountyos
docker compose restart bountyos
docker compose down
docker compose up -d
```

BountyOS listens on `http://127.0.0.1:8080` on the VPS. Use Nginx and TLS for public access.

## 6. Nginx reverse proxy and SSL

Copy the sample config and replace `YOUR_DOMAIN_HERE`:

```bash
sudo cp deploy/nginx/bountyos.conf /etc/nginx/sites-available/bountyos.conf
sudo sed -i 's/YOUR_DOMAIN_HERE/app.example.com/g' /etc/nginx/sites-available/bountyos.conf
sudo ln -s /etc/nginx/sites-available/bountyos.conf /etc/nginx/sites-enabled/bountyos.conf
sudo nginx -t
sudo systemctl reload nginx
```

Install Certbot and issue TLS:

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d app.example.com
```

The Nginx config includes WebSocket upgrade headers for live scan events and runner bridge connections.

## 7. Runner setup flow

The Cloud/VPS app container should not include heavy VM/Docker runner tools. Use a separate Kali/Ubuntu/Parrot host or container for runner tools.

1. Open BountyOS → Runners.
2. Create a runner and copy the one-time `runner_id` and `token`.
3. On the runner machine, install Python dependencies and tools.
4. Start the runner:

```bash
export SERVER=https://app.example.com
export RUNNER_ID=PASTE_RUNNER_ID
export RUNNER_TOKEN=PASTE_RUNNER_TOKEN
export RUNNER_NAME=bountyos-kali-runner
export RUNNER_LABELS=kali,self-hosted,77-tools,container
./scripts/start-runner-docker.sh
```

For a runner container talking to the host app, the script defaults `SERVER` to `http://host.docker.internal:8080`.

## 8. Update flow

```bash
./update.sh
```

The update script runs `git pull --ff-only`, rebuilds the Docker image, restarts the stack, and prints recent app logs.

## 9. Backup and restore

Back up Postgres regularly:

```bash
mkdir -p backups
docker compose exec -T postgres pg_dump -U bountyos bountyos > backups/bountyos-$(date +%F).sql
```

Restore into a fresh database:

```bash
cat backups/bountyos-YYYY-MM-DD.sql | docker compose exec -T postgres psql -U bountyos bountyos
```

Also back up `.env` securely outside Git. Never commit `.env`, runner tokens, Gemini API keys, database passwords, or exported scan data that contains secrets.

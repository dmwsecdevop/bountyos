# BountyOS v6 Cloud Run Deployment

BountyOS v6 runs on FastAPI with a prebuilt React dashboard in `static/`. The Cloud Run service should host the web/API container only; VM/Docker runner tools connect over the authenticated outbound runner WebSocket and run outside Cloud Run.

## Required placeholders

Replace these placeholders before deployment:

- `PROJECT_ID`: your Google Cloud project id, for example `my-bountyos-prod`
- `REGION`: Cloud Run and Cloud SQL region, for example `us-central1`
- `SERVICE_NAME`: Cloud Run service name, for example `bountyos`
- `INSTANCE_NAME`: Cloud SQL instance name, for example `bountyos-db`
- `INSTANCE_CONNECTION_NAME`: `PROJECT_ID:REGION:INSTANCE_NAME`
- `DB_NAME`: Postgres database name, for example `bountyos`
- `DB_USER`: Postgres user, for example `bountyos_user`
- `DB_PASSWORD`: a strong generated database password stored only in Secret Manager
- `DATABASE_URL_SECRET`: Secret Manager secret containing the SQLAlchemy URL

## Gemini or Vertex AI only

BountyOS v6 uses Gemini/Vertex routing only. Do not configure Claude, Anthropic, or Anthropic SDK credentials.

For Gemini Developer API, configure:

```bash
GEMINI_API_KEY=YOUR_GEMINI_DEVELOPER_API_KEY
BOUNTYOS_MAIN_PROVIDER=gemini
BOUNTYOS_MAIN_MODEL=gemini-2.5-flash
BOUNTYOS_VERSION=6.0.0
```

For Vertex AI, configure:

```bash
GOOGLE_CLOUD_PROJECT=PROJECT_ID
GOOGLE_CLOUD_LOCATION=REGION
GOOGLE_GENAI_USE_VERTEXAI=true
BOUNTYOS_MAIN_PROVIDER=vertex
BOUNTYOS_MAIN_MODEL=gemini-2.5-flash
BOUNTYOS_VERSION=6.0.0
```

## Cloud SQL Postgres

Create Cloud SQL and store the Unix-socket `DATABASE_URL` in Secret Manager:

```bash
gcloud sql instances create INSTANCE_NAME \
  --project=PROJECT_ID \
  --database-version=POSTGRES_16 \
  --region=REGION \
  --tier=db-f1-micro

gcloud sql databases create DB_NAME --instance=INSTANCE_NAME --project=PROJECT_ID

gcloud sql users create DB_USER \
  --instance=INSTANCE_NAME \
  --project=PROJECT_ID \
  --password='DB_PASSWORD'

printf 'postgresql+psycopg://DB_USER:DB_PASSWORD@/DB_NAME?host=/cloudsql/INSTANCE_CONNECTION_NAME' | \
  gcloud secrets create DATABASE_URL_SECRET --project=PROJECT_ID --data-file=-
```

## Deploy

Build the dashboard first and copy `dashboard/dist/*` into `static/` before deploying from source.

```bash
gcloud run deploy SERVICE_NAME \
  --project=PROJECT_ID \
  --source . \
  --region=REGION \
  --platform=managed \
  --memory=2Gi \
  --cpu=2 \
  --timeout=900 \
  --add-cloudsql-instances=INSTANCE_CONNECTION_NAME \
  --set-secrets=DATABASE_URL=DATABASE_URL_SECRET:latest \
  --set-env-vars=BOUNTYOS_VERSION=6.0.0,BOUNTYOS_EXECUTION_MODE=hybrid,BOUNTYOS_MAIN_PROVIDER=gemini \
  --no-allow-unauthenticated
```

See also `docs/CLOUD_RUN_DEPLOY.md` and `docs/CLOUD_SQL_POSTGRES.md`.

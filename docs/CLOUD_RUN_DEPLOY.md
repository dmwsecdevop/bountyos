# Cloud Run Deploy Guide

BountyOS can run on Cloud Run in passive/default-safe mode. Keep the service private for personal use unless you have added your own auth layer.

```bash
gcloud config set project bountyos
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com secretmanager.googleapis.com
gcloud run deploy bountyos \
  --source . \
  --region asia-south1 \
  --platform managed \
  --memory 2Gi \
  --cpu 2 \
  --timeout 900 \
  --set-env-vars BOUNTYOS_EXECUTION_MODE=passive,BOUNTYOS_MAIN_PROVIDER=gemini \
  --no-allow-unauthenticated
```

SQLite is acceptable for temporary personal testing, but Cloud SQL Postgres is recommended for persistent targets, scans, findings, agent tasks, and knowledge graph state.

## Deploy with Cloud SQL Postgres

See [`docs/CLOUD_SQL_POSTGRES.md`](CLOUD_SQL_POSTGRES.md). Cloud Run needs `--add-cloudsql-instances`, and `DATABASE_URL` should come from Secret Manager. Do not commit database passwords to GitHub.

## Safety notes

- Aggressive tools require authorization and explicit approval.
- Heavy scanners should run on a remote runner, not the main Cloud Run web image.
- Sandbox Runner is intentionally not included in this upgrade.

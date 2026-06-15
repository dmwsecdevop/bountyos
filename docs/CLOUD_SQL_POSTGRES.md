# Cloud SQL Postgres for BountyOS

BountyOS defaults to SQLite locally and supports Google Cloud SQL Postgres in production through `DATABASE_URL`.

Enable APIs:

```bash
gcloud services enable sqladmin.googleapis.com secretmanager.googleapis.com run.googleapis.com cloudbuild.googleapis.com
```

Create Cloud SQL Postgres instance:

```bash
gcloud sql instances create bountyos-db \
  --database-version=POSTGRES_16 \
  --region=asia-south1 \
  --tier=db-f1-micro \
  --storage-size=10GB
```

Create database:

```bash
gcloud sql databases create bountyos \
  --instance=bountyos-db
```

Create user:

```bash
gcloud sql users create bountyos_user \
  --instance=bountyos-db \
  --password='CHANGE_THIS_STRONG_PASSWORD'
```

Store `DATABASE_URL` in Secret Manager:

```bash
printf 'postgresql+psycopg://bountyos_user:CHANGE_THIS_STRONG_PASSWORD@/bountyos?host=/cloudsql/PROJECT_ID:asia-south1:bountyos-db' | \
gcloud secrets create bountyos-database-url --data-file=-
```

Grant Cloud Run service account access to the secret:

```bash
gcloud secrets add-iam-policy-binding bountyos-database-url \
  --member="serviceAccount:YOUR_SERVICE_ACCOUNT" \
  --role="roles/secretmanager.secretAccessor"
```

Deploy Cloud Run with Cloud SQL connection:

```bash
gcloud run deploy bountyos \
  --source . \
  --region asia-south1 \
  --platform managed \
  --memory 2Gi \
  --cpu 2 \
  --timeout 900 \
  --add-cloudsql-instances PROJECT_ID:asia-south1:bountyos-db \
  --set-secrets DATABASE_URL=bountyos-database-url:latest \
  --set-env-vars BOUNTYOS_EXECUTION_MODE=passive,BOUNTYOS_MAIN_PROVIDER=gemini \
  --no-allow-unauthenticated
```

Replace `PROJECT_ID` with your actual project id. For this repo the project may be `bountyos` if that is the active Google Cloud project. Use Secret Manager, not plain env vars, for database passwords. SQLite is okay only for temporary personal testing; Cloud SQL is recommended for persistence.

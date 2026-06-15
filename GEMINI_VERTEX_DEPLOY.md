# BountyOS v5.1 — Gemini / Vertex AI migration

This build replaces active Anthropic/Claude calls with the official `google-genai`
SDK while preserving the existing BountyOS agent loops and function-calling tools.

## Runtime model routing

- General chat / command triage: `gemini-2.5-flash-lite`
- Passive recon planning: `gemini-2.5-flash`
- Deep scan and finding analysis: `gemini-2.5-pro`
- Aggressive and approved validation reasoning: `gemini-2.5-pro`
- Live currency/CVE/crypto queries: deterministic live-data connectors

All model IDs are environment variables and can be changed without code edits.

## Required GCP access

The Cloud Run service and worker VM service account must have:

```bash
gcloud projects add-iam-policy-binding bountyos \
  --member='serviceAccount:746092862007-compute@developer.gserviceaccount.com' \
  --role='roles/aiplatform.user'
```

The user's environment already confirmed this account is attached to both runtimes.

## Build and deploy safely

Keep the current working Cloud Run revision available for rollback. From this source directory:

```bash
PROJECT_ID=bountyos \
SERVICE_NAME=bountyos \
REGION=asia-south1 \
SERVICE_ACCOUNT=746092862007-compute@developer.gserviceaccount.com \
./scripts/deploy_cloud_run_gemini.sh --no-traffic --tag gemini-test
```

Get the tagged test URL:

```bash
gcloud run services describe bountyos \
  --region asia-south1 \
  --format='value(status.traffic[?tag==`gemini-test`].url)'
```

Test these endpoints on the tagged revision:

```bash
curl "$TEST_URL/health"
curl "$TEST_URL/api/v1/ai/provider"
curl -X POST "$TEST_URL/api/v1/ai/provider/test"
```

When the Gemini provider test succeeds, move traffic:

```bash
gcloud run services update-traffic bountyos \
  --region asia-south1 \
  --to-latest
```

## Developer API fallback

For local testing without Vertex AI, set:

```bash
export BOUNTYOS_AI_PROVIDER=gemini
export GEMINI_API_KEY='...'
```

Do not set an API key for the production Vertex deployment; use the attached GCP
service account instead.

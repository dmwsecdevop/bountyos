#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-bountyos}"
SERVICE_NAME="${SERVICE_NAME:-bountyos}"
REGION="${REGION:-asia-south1}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-746092862007-compute@developer.gserviceaccount.com}"

exec gcloud run deploy "$SERVICE_NAME" \
  --source . \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --service-account "$SERVICE_ACCOUNT" \
  --set-env-vars "BOUNTYOS_AI_PROVIDER=vertex,GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_CLOUD_LOCATION=global,GOOGLE_GENAI_USE_VERTEXAI=true,BOUNTYOS_LIGHT_MODEL=gemini-2.5-flash-lite,BOUNTYOS_RECON_MODEL=gemini-2.5-flash,BOUNTYOS_MAIN_MODEL=gemini-2.5-pro,BOUNTYOS_AGGRESSIVE_MODEL=gemini-2.5-pro,BOUNTYOS_EXPLOIT_MODEL=gemini-2.5-pro" \
  "$@"

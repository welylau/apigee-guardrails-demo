#!/usr/bin/env bash
# Creates the API product, developer and app used ONLY by the OWASP suite, and stores the app key in
# Secret Manager. Idempotent. The demo key (modelarmor-streaming-product) is never touched.
#   KIND=ratelimit (default): low limits, used by the burst test (API4-01)
#   KIND=suite              : high quota, used for every other suite call so test runs never eat the
#                             playground's 5,000/hour demo quota
#
#   ./tests/owasp/setup_ratelimit_app.sh              # rate-limit test app
#   KIND=suite ./tests/owasp/setup_ratelimit_app.sh   # suite app
#   ./tests/owasp/setup_ratelimit_app.sh --delete     # remove that KIND's app, product and secret
set -euo pipefail

ORG="${ORG:-YOUR_GCP_PROJECT_ID}"
PROJECT="${PROJECT:-YOUR_GCP_PROJECT_ID}"
ENV_NAME="${ENV_NAME:-default-dev}"
KIND="${KIND:-ratelimit}"
DEV_EMAIL="guardrail-ratelimit-tests@example.com"
if [[ "$KIND" == "suite" ]]; then
  PRODUCT="guardrail-owasp-suite"; APP="guardrail-owasp-suite-app"; SECRET="guardrail-owasp-suite-key"
  DISPLAY="Guardrail OWASP suite runner"; DESC="High quota for OWASP suite runs only. Not for demo use."
  QUOTA=30000; QUNIT=hour; SPIKE=3000pm
else
  PRODUCT="guardrail-ratelimit-test"; APP="guardrail-ratelimit-test-app"; SECRET="guardrail-ratelimit-test-key"
  DISPLAY="Guardrail rate-limit test (OWASP suite)"; DESC="Low limits for the OWASP API4 burst test only. Not for demo use."
  QUOTA=30; QUNIT=minute; SPIKE=6pm
fi
CLI=(apigeecli -o "$ORG" --default-token --disable-check)

if [[ "${1:-}" == "--delete" ]]; then
  "${CLI[@]}" apps delete --name "$APP" --id "$DEV_EMAIL" >/dev/null 2>&1 || true
  "${CLI[@]}" products delete --name "$PRODUCT" >/dev/null 2>&1 || true
  gcloud secrets delete "$SECRET" --project "$PROJECT" --quiet >/dev/null 2>&1 || true
  echo "Deleted $KIND test product, app and secret (developer kept; delete it once both apps are gone)."
  exit 0
fi

# 1) API product: proxy reads attribute spike_rate for SpikeArrest and the product quota for Quota.
if ! "${CLI[@]}" products get --name "$PRODUCT" >/dev/null 2>&1; then
  "${CLI[@]}" products create --name "$PRODUCT" --display-name "$DISPLAY" --desc "$DESC" \
    --envs "$ENV_NAME" --proxies guardrail-proxy --approval auto \
    --quota "$QUOTA" --interval 1 --unit "$QUNIT" --attrs "spike_rate=$SPIKE,access=private" >/dev/null
  echo "Created API product $PRODUCT ($QUOTA per $QUNIT, spike $SPIKE)"
else
  echo "API product $PRODUCT exists"
fi

# 2) Developer
if ! "${CLI[@]}" developers get --email "$DEV_EMAIL" >/dev/null 2>&1; then
  "${CLI[@]}" developers create --email "$DEV_EMAIL" --first Guardrail --last RateLimitTests --user guardrail-ratelimit-tests >/dev/null
  echo "Created developer $DEV_EMAIL"
else
  echo "Developer $DEV_EMAIL exists"
fi

# 3) App + key
if ! "${CLI[@]}" apps get --name "$APP" 2>/dev/null | grep -q consumerKey; then  # exits 0 even when missing
  "${CLI[@]}" apps create --name "$APP" --email "$DEV_EMAIL" --prods "$PRODUCT" >/dev/null
  echo "Created app $APP"
else
  echo "App $APP exists"
fi
KEY="$("${CLI[@]}" apps get --name "$APP" | python3 -c 'import json,sys; d=json.load(sys.stdin); d=d[0] if isinstance(d,list) else d; print(d["credentials"][0]["consumerKey"])')"

# 4) Secret Manager (the key is never printed)
if ! gcloud secrets describe "$SECRET" --project "$PROJECT" >/dev/null 2>&1; then
  gcloud secrets create "$SECRET" --project "$PROJECT" --replication-policy automatic --labels app=guardrail-proxy,purpose=owasp-suite >/dev/null
fi
printf '%s' "$KEY" | gcloud secrets versions add "$SECRET" --project "$PROJECT" --data-file=- >/dev/null
echo "Stored the test app key in Secret Manager: $SECRET"
echo "Run the suite with: APIGEE_RATELIMIT_TEST_KEY=\$(gcloud secrets versions access latest --secret $SECRET --project $PROJECT)"

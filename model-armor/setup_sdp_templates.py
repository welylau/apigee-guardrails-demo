"""Step 4 (P6): Model Armor Sensitive Data Protection for guardrail-proxy. Idempotent.

Creates / updates:
  1. SDP inspect template   projects/<p>/locations/us/inspectTemplates/guardrail-proxy-sdp
     High-risk identifiers only (APAC national IDs, payment cards, IBAN, Google Cloud credentials).
     Email / phone on their own are deliberately NOT included: normal prompts contain contact details.
  2. Model Armor templates  guardrail-proxy-inbound / guardrail-proxy-outbound
     Exact copies of the shared ma-ai-gw-inbound / -outbound filters + sdpSettings.advancedConfig.
     The shared templates (used by other demos) are never modified.

  python3 model-armor/setup_sdp_templates.py            # create / update
  python3 model-armor/setup_sdp_templates.py --dry-run  # print the payloads only
IAM (run separately, once): Model Armor's service agent needs roles/dlp.user + roles/dlp.reader.
"""
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

PROJECT = os.environ.get("PROJECT", "YOUR_GCP_PROJECT_ID")
LOC = "us"
DRY = "--dry-run" in sys.argv
SDP_ID = "guardrail-proxy-sdp"
SDP_NAME = f"projects/{PROJECT}/locations/{LOC}/inspectTemplates/{SDP_ID}"
COPIES = {"guardrail-proxy-inbound": "ma-ai-gw-inbound", "guardrail-proxy-outbound": "ma-ai-gw-outbound"}

INFO_TYPES = [
    "SINGAPORE_NATIONAL_REGISTRATION_ID_NUMBER", "SINGAPORE_PASSPORT", "HONG_KONG_ID_NUMBER",
    "TAIWAN_ID_NUMBER", "THAILAND_NATIONAL_ID_NUMBER", "INDONESIA_NIK_NUMBER", "INDIA_AADHAAR_INDIVIDUAL",
    "INDIA_PAN_INDIVIDUAL", "JAPAN_INDIVIDUAL_NUMBER", "KOREA_RRN", "AUSTRALIA_TAX_FILE_NUMBER",
    "CREDIT_CARD_NUMBER", "IBAN_CODE", "GCP_API_KEY", "GCP_CREDENTIALS",
]
CUSTOM = [{  # no built-in Malaysia NRIC detector: YYMMDD-PB-###G
    "infoType": {"name": "MALAYSIA_NRIC_CUSTOM"},
    "regex": {"pattern": r"\b\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])-\d{2}-\d{4}\b"},
    "likelihood": "LIKELY",
}]

TOKEN = subprocess.run(["gcloud", "auth", "application-default", "print-access-token"], capture_output=True, text=True,
                       env={**os.environ, "CLOUDSDK_METRICS_ENVIRONMENT": "datacloud.jetski"}).stdout.strip()


def call(method, url, body=None):
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {TOKEN}", "x-goog-user-project": PROJECT,
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


# 1) SDP inspect template
DLP = f"https://dlp.googleapis.com/v2/projects/{PROJECT}/locations/{LOC}/inspectTemplates"
inspect = {"displayName": "guardrail-proxy high-risk identifiers",
           "description": "APAC national IDs, payment cards, IBAN, Google Cloud credentials (OWASP LLM02). Used by Model Armor.",
           "inspectConfig": {"infoTypes": [{"name": n} for n in INFO_TYPES], "customInfoTypes": CUSTOM,
                             "minLikelihood": "LIKELY", "includeQuote": False}}
if DRY:
    print(json.dumps(inspect, indent=1))
else:
    st, r = call("GET", f"{DLP}/{SDP_ID}")
    if st == 200:
        st, r = call("PATCH", f"{DLP}/{SDP_ID}", {"inspectTemplate": inspect, "updateMask": "displayName,description,inspectConfig"})
        print("SDP inspect template updated" if st == 200 else f"SDP update failed {st}: {r}")
    else:
        st, r = call("POST", DLP, {"templateId": SDP_ID, "inspectTemplate": inspect})
        print("SDP inspect template created" if st == 200 else f"SDP create failed {st}: {r}")
    if st != 200:
        sys.exit(1)

# 2) Model Armor templates: copy the shared ones + SDP advanced config
MA = f"https://modelarmor.{LOC}.rep.googleapis.com/v1/projects/{PROJECT}/locations/{LOC}/templates"
for new, src in COPIES.items():
    st, base = call("GET", f"{MA}/{src}")
    if st != 200:
        sys.exit(f"cannot read {src}: {st} {base}")
    filt = dict(base["filterConfig"])
    filt["sdpSettings"] = {"advancedConfig": {"inspectTemplate": SDP_NAME}}
    meta = dict(base.get("templateMetadata", {}))
    # Org policy constraints/modelarmor.managed.requireTemplateDataResidencyCompliance: new templates
    # must enforce data residency (the shared inbound template predates the policy and has it off).
    meta["dataResidencyCompliant"] = True
    tpl = {"filterConfig": filt, "templateMetadata": meta,
           "labels": {"app": "guardrail-proxy", "copied-from": src}}
    if DRY:
        print(new, json.dumps(tpl, indent=1))
        continue
    st, r = call("GET", f"{MA}/{new}")
    if st == 200:
        st, r = call("PATCH", f"{MA}/{new}?updateMask=filterConfig,templateMetadata,labels", tpl)
        print(f"{new} updated" if st == 200 else f"{new} update failed {st}: {r}")
    else:
        st, r = call("POST", f"{MA}?templateId={new}", tpl)
        print(f"{new} created" if st == 200 else f"{new} create failed {st}: {r}")
    if st != 200:
        sys.exit(1)
print("done" if not DRY else "dry run only")

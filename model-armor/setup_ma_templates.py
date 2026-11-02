"""Model Armor preset templates for apigee-guardrails-demo (guardrail-proxy). Idempotent, stdlib only.

Creates / updates (location us):
  SDP inspect template  guardrail-proxy-sdp            APAC national IDs, payment cards, IBAN, GCP credentials
  Model Armor templates guardrail-proxy-{in|out}-{strict|balanced|permissive}

Preset levels (one setting for the audience):
  strict     = LOW_AND_ABOVE     (catches the most, more false positives)
  balanced   = MEDIUM_AND_ABOVE  (default)
  permissive = HIGH              (only clear-cut matches)
  The level applies to the 4 RAI filters and to inbound prompt-injection/jailbreak.
  Outbound prompt-injection/jailbreak is fixed at HIGH in every preset: at lower levels it cuts off
  streamed answers that merely discuss injection. SDP, malicious URI and CSAM have no confidence level.

Usage:
  python3 model-armor/setup_ma_templates.py --dry-run   # show payloads + what would change, no writes
  python3 model-armor/setup_ma_templates.py             # create / update
  python3 model-armor/setup_ma_templates.py --check     # report drift between live templates and this file

Do not edit these templates in the console; change this file and re-run.
IAM (once): Model Armor's service agent needs roles/dlp.user + roles/dlp.reader for the SDP template.
"""
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

PROJECT = os.environ.get("PROJECT", "YOUR_GCP_PROJECT_ID")
LOC = "us"
MODE = "dry-run" if "--dry-run" in sys.argv else "check" if "--check" in sys.argv else "apply"

PREFIX = "guardrail-proxy"
LEVELS = {"strict": "LOW_AND_ABOVE", "balanced": "MEDIUM_AND_ABOVE", "permissive": "HIGH"}
OUTBOUND_PI_LEVEL = "HIGH"
RAI_TYPES = ["HATE_SPEECH", "HARASSMENT", "SEXUALLY_EXPLICIT", "DANGEROUS"]

SDP_ID = f"{PREFIX}-sdp"
SDP_NAME = f"projects/{PROJECT}/locations/{LOC}/inspectTemplates/{SDP_ID}"
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
SDP_TEMPLATE = {
    "displayName": "guardrail-proxy high-risk identifiers",
    "description": "apigee-guardrails-demo: APAC national IDs, payment cards, IBAN, Google Cloud credentials "
                   "(OWASP LLM02). Used by Model Armor templates guardrail-proxy-*.",
    "inspectConfig": {"infoTypes": [{"name": n} for n in INFO_TYPES], "customInfoTypes": CUSTOM,
                      "minLikelihood": "LIKELY", "includeQuote": False},
}

LABELS = {"demo": "apigee-guardrails-demo", "app": "guardrail-proxy",
          "managed-by": "setup-ma-templates", "source": "model-armor_setup_ma_templates_py"}
METADATA = {
    "enforcementType": "INSPECT_AND_BLOCK",
    "multiLanguageDetection": {"enableMultiLanguageDetection": True},
    "logTemplateOperations": True,
    "logSanitizeOperations": True,
    "filterVersionSelector": {"alias": "FILTER_VERSION_ALIAS_STABLE"},
    "modalities": ["MODALITY_TEXT", "MODALITY_IMAGE"],
    # Org policy constraints/modelarmor.managed.requireTemplateDataResidencyCompliant
    "dataResidencyCompliant": True,
}


def template(direction, preset):
    level = LEVELS[preset]
    pi_level = level if direction == "inbound" else OUTBOUND_PI_LEVEL
    return {
        "filterConfig": {
            "raiSettings": {"raiFilters": [{"filterType": t, "confidenceLevel": level} for t in RAI_TYPES]},
            "piAndJailbreakFilterSettings": {"filterEnforcement": "ENABLED", "confidenceLevel": pi_level},
            "maliciousUriFilterSettings": {"filterEnforcement": "ENABLED"},
            "sdpSettings": {"advancedConfig": {"inspectTemplate": SDP_NAME}},
        },
        "templateMetadata": METADATA,
        "labels": dict(LABELS, direction=direction, preset=preset),
    }


SHORT = {"inbound": "in", "outbound": "out"}
TEMPLATES = {f"{PREFIX}-{SHORT[d]}-{p}": template(d, p) for d in SHORT for p in LEVELS}
# -> guardrail-proxy-in-strict, -in-balanced, -in-permissive, -out-strict, -out-balanced, -out-permissive

TOKEN = subprocess.run(["gcloud", "auth", "application-default", "print-access-token"], capture_output=True, text=True,
                       env={**os.environ, "CLOUDSDK_METRICS_ENVIRONMENT": "datacloud.jetski"}).stdout.strip()
if not TOKEN:
    sys.exit("no ADC token: run `gcloud auth application-default login`")


def call(method, url, body=None):
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {TOKEN}", "x-goog-user-project": PROJECT,
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def diff(want, have, path=""):
    """Fields in `want` that differ from `have` (server-added fields are ignored)."""
    out = []
    if isinstance(want, dict):
        for k, v in want.items():
            out += diff(v, (have or {}).get(k) if isinstance(have, dict) else None, f"{path}.{k}" if path else k)
    elif isinstance(want, list) and want and isinstance(want[0], dict) and "filterType" in want[0]:
        have_map = {r.get("filterType"): r.get("confidenceLevel") for r in (have or [])}
        out += [f"{path}[{r['filterType']}]: {have_map.get(r['filterType'])} -> {r['confidenceLevel']}"
                for r in want if have_map.get(r["filterType"]) != r["confidenceLevel"]]
    elif want != have and not (have is None and want in (False, 0, "", [], {})):  # APIs omit default values
        out.append(f"{path}: {json.dumps(have)} -> {json.dumps(want)}")
    return out


changes = 0

# 1) SDP inspect template
DLP = f"https://dlp.googleapis.com/v2/projects/{PROJECT}/locations/{LOC}/inspectTemplates"
st, live = call("GET", f"{DLP}/{SDP_ID}")
d = diff(SDP_TEMPLATE, live) if st == 200 else ["(new)"]
print(f"[SDP] {SDP_ID}: {'exists' if st == 200 else 'missing'} | {'no change' if not d else f'{len(d)} change(s)'}")
for line in d:
    print(f"      {line}")
if d and MODE == "apply":
    if st == 200:
        st, r = call("PATCH", f"{DLP}/{SDP_ID}",
                     {"inspectTemplate": SDP_TEMPLATE, "updateMask": "displayName,description,inspectConfig"})
    else:
        st, r = call("POST", DLP, {"templateId": SDP_ID, "inspectTemplate": SDP_TEMPLATE})
    print(f"      -> {'ok' if st == 200 else f'FAILED {st}: {r}'}")
    if st != 200:
        sys.exit(1)
changes += bool(d)

# 2) Model Armor templates
MA = f"https://modelarmor.{LOC}.rep.googleapis.com/v1/projects/{PROJECT}/locations/{LOC}/templates"
for tid, tpl in TEMPLATES.items():
    st, live = call("GET", f"{MA}/{tid}")
    exists = st == 200
    d = diff(tpl, live) if exists else []
    state = "no change" if exists and not d else (f"{len(d)} change(s)" if exists else "CREATE")
    f = tpl["filterConfig"]
    print(f"[MA]  {tid:32s} {state:12s} RAI={f['raiSettings']['raiFilters'][0]['confidenceLevel']:17s} "
          f"PI={f['piAndJailbreakFilterSettings']['confidenceLevel']}")
    for line in d:
        print(f"      {line}")
    if MODE == "dry-run" and not exists and "--verbose" in sys.argv:
        print(json.dumps(tpl, indent=1))
    if MODE == "apply" and (not exists or d):
        if exists:
            st, r = call("PATCH", f"{MA}/{tid}?updateMask=filterConfig,templateMetadata,labels", tpl)
        else:
            st, r = call("POST", f"{MA}?templateId={tid}", tpl)
        print(f"      -> {'ok' if st == 200 else f'FAILED {st}: {r}'}")
        if st != 200:
            sys.exit(1)
    changes += (not exists) or bool(d)

print(f"\n{MODE}: {changes} resource(s) {'would change' if MODE != 'apply' else 'changed'}")
if MODE == "check" and changes:
    sys.exit(2)

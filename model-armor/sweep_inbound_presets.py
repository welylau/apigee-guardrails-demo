"""Phase B: inbound preset sweep straight against Model Armor (no Apigee, no LLM tokens).

Sends every inbound case of the curated + extended test-lab sets to each inbound template and reports
catch rate on attacks, false-positive rate on benign prompts, per-language breakdown and latency.
The deprecated guardrail-proxy-inbound (MEDIUM, multi-language off) is included as a control.

  python3 model-armor/sweep_inbound_presets.py [--limit N] [--workers 8]
Writes model-armor/sweep_results.json
"""
import json
import os
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

PROJECT = os.environ.get("PROJECT", "YOUR_GCP_PROJECT_ID")
LOC = "us"
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SETS = {"curated": "demo-ui/static/testlab/results-latest.json",
        "extended": "demo-ui/static/testlab/results-latest-extended.json"}
TEMPLATES = ["guardrail-proxy-inbound", "guardrail-proxy-in-permissive",
             "guardrail-proxy-in-balanced", "guardrail-proxy-in-strict"]
LIMIT = int(sys.argv[sys.argv.index("--limit") + 1]) if "--limit" in sys.argv else None
WORKERS = int(sys.argv[sys.argv.index("--workers") + 1]) if "--workers" in sys.argv else 8

TOKEN = subprocess.run(["gcloud", "auth", "application-default", "print-access-token"],
                       capture_output=True, text=True).stdout.strip()
BASE = f"https://modelarmor.{LOC}.rep.googleapis.com/v1/projects/{PROJECT}/locations/{LOC}/templates"


def sanitize(tid, text):
    body = json.dumps({"userPromptData": {"text": text}}).encode()
    for attempt in range(4):
        req = urllib.request.Request(f"{BASE}/{tid}:sanitizeUserPrompt", data=body, method="POST",
                                     headers={"Authorization": f"Bearer {TOKEN}", "x-goog-user-project": PROJECT,
                                              "Content-Type": "application/json"})
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                res = json.loads(r.read())["sanitizationResult"]
            ms = int((time.time() - t0) * 1000)
            fr = res.get("filterResults", {})
            hits = []
            for k, v in fr.items():
                inner = next(iter(v.values()), {}) if isinstance(v, dict) else {}
                if k == "rai":
                    hits += [f"rai:{t}" for t, x in inner.get("raiFilterTypeResults", {}).items()
                             if x.get("matchState") == "MATCH_FOUND"]
                elif k == "sdp":
                    st = inner.get("inspectResult", {}).get("matchState")
                    if st == "MATCH_FOUND":
                        hits.append("sdp")
                elif inner.get("matchState") == "MATCH_FOUND":
                    hits.append(k)
            return {"match": res.get("filterMatchState") == "MATCH_FOUND", "hits": hits, "ms": ms}
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 503) and attempt < 3:
                time.sleep(2 ** attempt)
                continue
            return {"error": f"{e.code} {e.read().decode()[:120]}"}
        except Exception as e:  # network blips
            if attempt < 3:
                time.sleep(2 ** attempt)
                continue
            return {"error": str(e)[:120]}


cases = []
for set_name, path in SETS.items():
    if not os.path.exists(os.path.join(ROOT, path)):
        print(f"skipping {set_name}: {path} is not in this copy of the repo")
        continue
    for c in json.load(open(os.path.join(ROOT, path)))["cases"]:
        if c.get("direction") == "inbound" and c.get("prompt"):
            cases.append({"set": set_name, "id": c["id"], "expected": c["expected"],
                          "language": c.get("language", "en"), "prompt": c["prompt"]})
if LIMIT:
    cases = cases[:LIMIT]
print(f"{len(cases)} inbound cases x {len(TEMPLATES)} templates = {len(cases) * len(TEMPLATES)} calls")

jobs = [(c, t) for c in cases for t in TEMPLATES]
with ThreadPoolExecutor(WORKERS) as ex:
    results = list(ex.map(lambda j: (j[0]["id"], j[1], sanitize(j[1], j[0]["prompt"])), jobs))
by = defaultdict(dict)
for cid, tid, r in results:
    by[cid][tid] = r
for c in cases:
    c["results"] = by[c["id"]]
json.dump({"templates": TEMPLATES, "cases": cases}, open(os.path.join(HERE, "sweep_results.json"), "w"), indent=1)

# report
for set_name in SETS:
    sub = [c for c in cases if c["set"] == set_name]
    att = [c for c in sub if c["expected"] == "block"]
    ben = [c for c in sub if c["expected"] == "pass"]
    print(f"\n== {set_name}: {len(att)} attacks, {len(ben)} benign")
    print(f"{'template':32s} {'caught':>14s} {'false pos':>12s} {'errors':>7s} {'p50 ms':>7s} {'p95 ms':>7s}")
    for t in TEMPLATES:
        ok = lambda c: "error" not in c["results"][t]
        caught = sum(c["results"][t].get("match", False) for c in att)
        fp = sum(c["results"][t].get("match", False) for c in ben)
        errs = sum(not ok(c) for c in sub)
        lat = sorted(c["results"][t]["ms"] for c in sub if ok(c))
        p50 = statistics.median(lat) if lat else 0
        p95 = lat[int(len(lat) * 0.95) - 1] if lat else 0
        print(f"{t:32s} {caught:4d}/{len(att):<4d}{caught / max(len(att), 1):5.0%} "
              f"{fp:3d}/{len(ben):<4d}{fp / max(len(ben), 1):4.0%} {errs:7d} {p50:7.0f} {p95:7.0f}")
    langs = sorted({c["language"] for c in att})
    print("catch rate by language (attacks):")
    for lang in langs:
        la = [c for c in att if c["language"] == lang]
        print(f"   {lang:8s} n={len(la):<4d} " + "  ".join(
            f"{t.replace('guardrail-proxy-', ''):14s}{sum(c['results'][t].get('match', False) for c in la):3d}"
            for t in TEMPLATES))
    print("false positives (benign prompts blocked):")
    for c in ben:
        flagged = [t.replace("guardrail-proxy-", "") for t in TEMPLATES if c["results"][t].get("match")]
        if flagged:
            hits = c["results"][flagged and f"guardrail-proxy-{flagged[-1]}"].get("hits")
            print(f"   {c['id']:14s} {','.join(flagged):45s} {hits} {c['prompt'][:60]!r}")

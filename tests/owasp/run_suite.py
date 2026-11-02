#!/usr/bin/env python3
"""Runs the 100-case OWASP guardrail suite against the live guardrail-proxy.

Runs per case (see the Test Lab plan):
  S  Static only      M  Model Armor only      N  NeMo only (each rail)      D  all layers on
  A  API-security cases (real HTTP behaviour: auth, overrides, limits, errors)

Usage:
  APIGEE_API_KEY=... python3 tests/owasp/run_suite.py [--label baseline] [--only LLM01-01,API2-01] [--workers 6]
                                                      [--set curated|extended] [--ma-profile strict|balanced|permissive]
Writes tests/owasp/results/<timestamp>-<label>.json and demo-ui/static/testlab/results-latest.json
(non-default Model Armor presets write results-latest[-extended]-<preset>.json so the default view is unchanged).
"""
import argparse
import concurrent.futures as cf
import datetime as dt
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import suite_http as H  # noqa: E402
from summarise import summarise  # noqa: E402

BASE_RAILS = ["jailbreak_self_check", "content_safety"]
SETS = {
    "curated": {"file": "cases.json", "latest": "results-latest.json"},
    "extended": {"file": "cases_extended.json", "latest": "results-latest-extended.json"},
}


def nemo_rails(case):
    rails = list(BASE_RAILS)
    if case.get("nemo_profile") and case["nemo_profile"] not in rails:
        rails.append(case["nemo_profile"])
    return rails


def run_case(case):
    if case["direction"] == "api":
        return {"A": H.call_api(case)}
    outbound = case["direction"] == "outbound"
    runs = {}
    # Isolation runs. Inbound cases only need the verdict headers; outbound cases need the stream.
    runs["S"] = H.call(case, "S", read_body=outbound)
    runs["M"] = H.call(case, "M", read_body=outbound)
    rails = {r: H.call(case, "N", profile=r, read_body=False) for r in nemo_rails(case)}
    blocked = [r for r, v in rails.items() if v["outcome"] == "nemo"]
    runs["N"] = {"outcome": "nemo" if blocked else ("pass" if all(v["outcome"] == "pass" for v in rails.values()) else
                                                     next(v["outcome"] for v in rails.values() if v["outcome"] != "pass")),
                 "blocked_by": blocked, "rails": rails,
                 "ms": max(v["ms"] for v in rails.values())}
    # Defense in depth: NeMo "all rails" (jailbreak + content safety, P5), or the case's business persona.
    d_profile = case.get("nemo_profile") or "all_rails"
    runs["D"] = H.call(case, "D", profile=d_profile, read_body=True)
    runs["D"]["nemo_profile"] = d_profile
    # Re-check inconsistent results (LLM judges vary a little between calls).
    iso_caught = any(runs[k]["outcome"] in H.CAUGHT for k in ("S", "M", "N"))
    d_caught = runs["D"]["outcome"] in H.CAUGHT
    if iso_caught != d_caught:
        retries = [H.call(case, "D", profile=d_profile, read_body=True)["outcome"] for _ in range(2)]
        runs["D"]["retries"] = retries
        runs["D"]["flaky"] = len({runs["D"]["outcome"], *retries}) > 1
    return runs


# Published runs shown as suite cards in the Test Lab (id -> file in demo-ui/static/testlab/).
INDEX_FILES = {
    "curated": "results-latest.json", "curated-strict": "results-latest-strict.json",
    "extended": "results-latest-extended.json", "extended-strict": "results-latest-extended-strict.json",
}


def write_index():
    """testlab/suites-index.json: one small entry per published run, for the suite cards."""
    lab = ROOT / "demo-ui" / "static" / "testlab"
    index = {}
    for sid, name in INDEX_FILES.items():
        f = lab / name
        if not f.exists():
            continue
        d = json.loads(f.read_text(encoding="utf-8"))
        sources = {}
        for c in d["cases"]:
            ds = (c.get("source") or {}).get("dataset") if isinstance(c.get("source"), dict) else None
            if ds:
                sources[ds] = sources.get(ds, 0) + 1
        index[sid] = {
            "label": d.get("label"), "run_at": d.get("run_at"), "duration_s": d.get("duration_s"),
            "cases": len(d["cases"]), "headline": d["summary"]["headline"],
            "fp_all_on": len(d["summary"].get("false_positives_all_on") or []), "sources": sources,
            "static_profile": d.get("static_profile"), "ma_profile": d.get("ma_profile"),
            **({"coverage": d.get("coverage", [])} if sid == "curated" else {}),
        }
    (lab / "suites-index.json").write_text(json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")
    return index


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="run")
    ap.add_argument("--only", default="")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--set", default="curated", choices=SETS,
                    help="curated = 102 hand-written cases; extended = 500 dataset + generated cases")
    ap.add_argument("--ma-profile", default="balanced", choices=H.MA_PROFILES,
                    help="Model Armor preset for runs M and D (templates guardrail-proxy-{in|out}-<preset>)")
    ap.add_argument("--static-profile", default="balanced", choices=H.STATIC_PROFILES,
                    help="Static Guardrails profile for runs S and D")
    ap.add_argument("--profile", choices=("strictest",),
                    help="shortcut: strictest = --static-profile strict --ma-profile strict (NeMo all rails is already the strictest)")
    ap.add_argument("--reindex", action="store_true", help="only rebuild demo-ui/static/testlab/suites-index.json")
    args = ap.parse_args()
    if args.reindex:
        print(json.dumps({k: (v["label"], v["run_at"], v["cases"]) for k, v in write_index().items()}, indent=1))
        return
    if args.profile == "strictest":
        args.static_profile, args.ma_profile = "strict", "strict"
    H.set_ma_profile(args.ma_profile)
    H.set_static_profile(args.static_profile)
    if not H.KEY:
        sys.exit("Set APIGEE_SUITE_KEY (suite test app) or APIGEE_API_KEY")
    case_file = HERE / SETS[args.set]["file"]
    if not case_file.exists():
        sys.exit(f"{case_file.name} is not in this copy of the repo; only the curated suite (--set curated) is published.")
    suite = json.loads(case_file.read_text(encoding="utf-8"))
    cases = suite["cases"]
    if args.only:
        wanted = set(args.only.split(","))
        cases = [c for c in cases if c["id"] in wanted]
    print(f"set={args.set} cases={len(cases)} static={args.static_profile} model_armor={args.ma_profile} "
          f"key={'suite app' if H.USING_SUITE_KEY else 'DEMO KEY (shares the playground quota)'}")
    started = dt.datetime.now(dt.timezone.utc)
    results = {}
    # API burst test runs alone at the end so it doesn't disturb the other calls.
    normal = [c for c in cases if not c.get("api", {}).get("burst")]
    burst = [c for c in cases if c.get("api", {}).get("burst")]
    with cf.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {pool.submit(run_case, c): c for c in normal}
        for i, f in enumerate(cf.as_completed(futs), 1):
            c = futs[f]
            try:
                results[c["id"]] = f.result()
            except Exception as e:  # keep going; record the failure
                results[c["id"]] = {"error": f"{type(e).__name__}: {e}"}
            r = results[c["id"]]
            main_out = (r.get("D") or r.get("A") or {}).get("outcome", r.get("error", "?"))
            print(f"[{i:>3}/{len(normal)}] {c['id']:<12} {main_out}", flush=True)
    for c in burst:
        results[c["id"]] = run_case(c)
        print(f"[burst] {c['id']:<9} {results[c['id']]['A']['outcome']} statuses={results[c['id']]['A']['statuses']}")

    strictest = args.static_profile == "strict" and args.ma_profile == "strict"
    out = {
        "label": args.label,
        "set": args.set,
        "set_description": suite.get("description", ""),
        "run_at": started.isoformat(timespec="seconds"),
        "duration_s": round((dt.datetime.now(dt.timezone.utc) - started).total_seconds()),
        "target": H.BASE.split("//")[-1].split("/", 1)[-1],
        "profile": "strictest" if strictest else ("balanced" if args.ma_profile == args.static_profile == "balanced" else "custom"),
        "static_profile": args.static_profile,
        "ma_profile": args.ma_profile,
        "nemo_profile": "all_rails (or the case's persona)",
        "ma_templates": {"inbound": f"guardrail-proxy-in-{args.ma_profile}",
                         "outbound": f"guardrail-proxy-out-{args.ma_profile}"},
        "config": {
            "S": f"Static Guardrails only ({args.static_profile}, inbound + outbound enforce)",
            "M": f"Model Armor only (SanitizeUserPrompt + SanitizeModelResponse, {args.ma_profile} preset)",
            "N": "NeMo only: jailbreak + content-safety rails (+ the case's persona topic rail)",
            "D": f"All layers on: Static {args.static_profile}, Model Armor in/out ({args.ma_profile}), NeMo all_rails (or the case's persona)",
            "A": "API-security cases: real HTTP behaviour of the gateway",
        },
        "coverage": suite.get("coverage", []),
        "cases": [{**c, "runs": results.get(c["id"], {})} for c in cases],
    }
    out["summary"] = summarise(out["cases"])
    stamp = started.strftime("%Y%m%d-%H%M%S")
    (HERE / "results").mkdir(exist_ok=True)
    hist = HERE / "results" / f"{stamp}-{args.label}-static-{args.static_profile}-ma-{args.ma_profile}.json"
    hist.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    if not args.only:
        latest_name = SETS[args.set]["latest"]
        # results-latest.json (balanced) · -strict.json (strictest) · -<preset>.json (Model Armor preset only)
        if strictest:
            latest_name = latest_name.replace(".json", "-strict.json")
        elif args.static_profile != "balanced":
            latest_name = latest_name.replace(".json", f"-static-{args.static_profile}-ma-{args.ma_profile}.json")
        elif args.ma_profile != "balanced":
            latest_name = latest_name.replace(".json", f"-{args.ma_profile}.json")
        latest = ROOT / "demo-ui" / "static" / "testlab" / latest_name
        latest.parent.mkdir(parents=True, exist_ok=True)
        latest.write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
        write_index()
    s = out["summary"]
    print(f"\nSaved {hist.relative_to(ROOT)}  ({out['duration_s']} s)")
    print(json.dumps(s["headline"], indent=1))


if __name__ == "__main__":
    main()

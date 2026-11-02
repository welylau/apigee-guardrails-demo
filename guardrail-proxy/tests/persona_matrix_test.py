#!/usr/bin/env python3
"""Live persona matrix through the deployed guardrail-proxy.

Sends every prompt in nemo-guardrails/personas.json -> test_matrix to Apigee with only
NeMo on (topic persona as x-nemo-profile, Monitor mode so nothing is blocked or streamed
needlessly) and compares the x-nemo-verdict header with the expected verdict.

Usage: APIGEE_API_KEY=... python3 guardrail-proxy/tests/persona_matrix_test.py [persona_id ...]
"""
import json
import os
import pathlib
import ssl
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE = os.environ.get("GUARDRAIL_URL", "https://YOUR_APIGEE_HOST/guardrail-proxy")
KEY = os.environ.get("APIGEE_API_KEY", "")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE  # nip.io demo endpoint


def nemo_verdict(prompt, persona):
    body = json.dumps({"contents": [{"role": "user", "parts": [{"text": prompt}]}]}).encode()
    req = urllib.request.Request(BASE, data=body, method="POST")
    for k, v in {
        "Content-Type": "application/json", "x-apikey": KEY,
        "x-static-guardrails": "disable", "x-static-outbound": "disable",
        "x-inbound": "disable", "x-outbound": "disable",
        "x-nemo-guardrails": "monitor", "x-nemo-profile": persona,
    }.items():
        req.add_header(k, v)
    t0 = time.time()
    try:
        # Headers arrive before the streamed body; close right after reading them.
        with urllib.request.urlopen(req, context=CTX, timeout=90) as r:
            h = r.headers
    except urllib.error.HTTPError as e:
        h = e.headers
    return h.get("x-nemo-verdict", "?"), h.get("x-nemo-profile", "?"), time.time() - t0


def main():
    if not KEY:
        sys.exit("Set APIGEE_API_KEY")
    only = set(sys.argv[1:])
    cases = json.loads((ROOT / "nemo-guardrails" / "personas.json").read_text(encoding="utf-8"))["test_matrix"]["cases"]
    fails = total = 0
    for case in cases:
        for persona, expected in case["expect"].items():
            if only and persona not in only:
                continue
            total += 1
            got, echoed, dt = nemo_verdict(case["prompt"], persona)
            ok = got == expected and echoed == persona
            fails += not ok
            print(f"{'PASS' if ok else 'FAIL'}  {case['id']:<11} {persona:<17} expected={expected:<5} "
                  f"got={got:<5} profile={echoed} ({dt:.1f}s)")
    print(f"\n{total - fails}/{total} as expected")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()

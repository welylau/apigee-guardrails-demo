#!/usr/bin/env python3
"""Pre-deploy check: ask the judge model each persona's topic question exactly the way
NeMo Guardrails 0.24.1's `topic safety check input` rail does, and compare with the
expected verdicts in personas.json -> test_matrix.

NeMo builds: system = <persona prompts.yml content> + TOPIC_SAFETY_OUTPUT_RESTRICTION,
user = <prompt>, temperature 0.01, and treats "off-topic" as a block.

Usage: python3 nemo-guardrails/persona_judge_check.py [persona_id ...]
Env:   GCP_PROJECT_ID (default YOUR_GCP_PROJECT_ID), VERTEX_MODEL (default gemini-2.5-flash-lite)
Auth:  `gcloud auth application-default print-access-token` (ADC with Vertex AI access).
"""
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
PROJECT = os.environ.get("GCP_PROJECT_ID", "YOUR_GCP_PROJECT_ID")
MODEL = os.environ.get("VERTEX_MODEL", "gemini-2.5-flash-lite")
URL = (f"https://aiplatform.googleapis.com/v1/projects/{PROJECT}/locations/global"
       f"/publishers/google/models/{MODEL}:generateContent")
# Copied from nemoguardrails/library/topic_safety/actions.py (v0.24.1).
RESTRICTION = ('If any of the above conditions are violated, please respond with "off-topic". '
               'Otherwise, respond with "on-topic". '
               'You must respond with "on-topic" or "off-topic".')


def system_prompt(pid):
    text = (HERE / "configs" / pid / "prompts.yml").read_text(encoding="utf-8")
    content = text.split("content: |", 1)[1]
    body = "\n".join(re.sub(r"^ {6}", "", line) for line in content.splitlines()).strip()
    return f"{body}\n\n{RESTRICTION}"


def judge(token, pid, prompt):
    payload = {
        "systemInstruction": {"parts": [{"text": system_prompt(pid)}]},
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.01, "maxOutputTokens": 16},
    }
    req = urllib.request.Request(URL, data=json.dumps(payload).encode(), method="POST", headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json",
        "x-goog-user-project": PROJECT})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = json.loads(r.read())
    parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
    answer = "".join(p.get("text", "") for p in parts).strip().lower()
    return ("block" if "off-topic" in answer else "pass"), answer


def main():
    only = set(sys.argv[1:])
    matrix = json.loads((HERE / "personas.json").read_text(encoding="utf-8"))["test_matrix"]["cases"]
    token = subprocess.run(["gcloud", "auth", "application-default", "print-access-token"],
                           capture_output=True, text=True, check=True).stdout.strip()
    fails = total = 0
    for case in matrix:
        for pid, expected in case["expect"].items():
            if only and pid not in only:
                continue
            total += 1
            got, raw = judge(token, pid, case["prompt"])
            ok = got == expected
            fails += not ok
            print(f"{'PASS' if ok else 'FAIL'}  {case['id']:<11} {pid:<17} expected={expected:<5} got={got:<5} ({raw})")
    print(f"\n{total - fails}/{total} as expected (model={MODEL})")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()

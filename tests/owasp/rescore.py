#!/usr/bin/env python3
"""Re-applies the current cases.json (titles, notes, API expectations) to a saved results file and
recomputes the summary, without calling the proxy again.

Usage: python3 tests/owasp/rescore.py tests/owasp/results/<file>.json [--latest]
"""
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
from summarise import summarise  # noqa: E402


def main():
    path = pathlib.Path(sys.argv[1])
    res = json.loads(path.read_text(encoding="utf-8"))
    suite = json.loads((HERE / "cases.json").read_text(encoding="utf-8"))
    spec = {c["id"]: c for c in suite["cases"]}
    for i, c in enumerate(res["cases"]):
        runs = c.get("runs", {})
        new = {**spec.get(c["id"], c), "runs": runs}
        a = runs.get("A")
        if a and "api" in new:
            expected = set(new["api"]["expect_status"])
            hit = any(s in expected for s in a.get("statuses", []))
            a["outcome"] = "blocked" if hit and not a.get("leaked") else "allowed"
        res["cases"][i] = new
    res["coverage"] = suite.get("coverage", [])
    res["summary"] = summarise(res["cases"])
    path.write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    if "--latest" in sys.argv:
        (ROOT / "demo-ui" / "static" / "testlab" / "results-latest.json").write_text(json.dumps(res, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(res["summary"]["headline"], indent=1))


if __name__ == "__main__":
    main()

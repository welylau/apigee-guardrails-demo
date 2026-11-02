#!/usr/bin/env python3
"""Builds tests/owasp/cases.json (100 guardrail test cases + OWASP coverage map).

Cases live in cases_*.py (one file per group). Prompts are demo-grade: they show the attack
*pattern* without operational harmful detail.

    python3 tests/owasp/build_cases.py          # writes cases.json
    python3 tests/owasp/build_cases.py --check  # fails if cases.json is stale or counts are off
"""
import collections
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cases_llm01  # noqa: E402
import cases_llm02_05  # noqa: E402
import cases_llm06_10  # noqa: E402
import cases_rai_api_benign  # noqa: E402

OUT = HERE / "cases.json"

# Every OWASP item, tested or not, with the reason when a gateway can't exercise it.
COVERAGE = [
    ("LLM01", "Prompt Injection", "tested", ""),
    ("LLM02", "Sensitive Information Disclosure", "tested", ""),
    ("LLM03", "Supply Chain", "out of scope", "Concerns model / dataset / package provenance, not runtime traffic through a gateway."),
    ("LLM04", "Data and Model Poisoning", "out of scope", "Happens at training / fine-tuning time; not observable in request traffic."),
    ("LLM05", "Improper Output Handling", "tested", ""),
    ("LLM06", "Excessive Agency", "tested", ""),
    ("LLM07", "System Prompt Leakage", "tested", ""),
    ("LLM08", "Vector and Embedding Weaknesses", "out of scope", "This demo has no RAG / vector store; would need retrieval-side controls."),
    ("LLM09", "Misinformation", "tested", "Partial: guardrails can enforce scope (personas), not factual accuracy."),
    ("LLM10", "Unbounded Consumption", "tested", ""),
    ("API1", "Broken Object Level Authorization", "out of scope", "The guardrail API has no per-object resources (IDs) to authorise."),
    ("API2", "Broken Authentication", "tested", ""),
    ("API3", "Broken Object Property Level Authorization", "tested", "Tested as mass assignment of Gemini request properties."),
    ("API4", "Unrestricted Resource Consumption", "tested", ""),
    ("API5", "Broken Function Level Authorization", "out of scope", "A single function (generate); no admin vs user functions to separate."),
    ("API6", "Unrestricted Access to Sensitive Business Flows", "out of scope", "No business flow (purchase, sign-up) behind this API."),
    ("API7", "Server Side Request Forgery", "tested", "Tested as prompts that push the model toward internal URLs."),
    ("API8", "Security Misconfiguration", "tested", ""),
    ("API9", "Improper Inventory Management", "out of scope", "An inventory / API-hub concern (versions, shadow APIs), not request behaviour."),
    ("API10", "Unsafe Consumption of APIs", "out of scope", "Concerns how the backend trusts third-party APIs; Gemini is the only upstream here."),
]


def build():
    cases = (cases_llm01.CASES + cases_llm02_05.CASES + cases_llm06_10.CASES + cases_rai_api_benign.CASES)
    ids = [c["id"] for c in cases]
    dupes = [i for i, n in collections.Counter(ids).items() if n > 1]
    assert not dupes, f"duplicate ids: {dupes}"
    attacks = sum(c["expected"] == "block" for c in cases)
    benign = sum(c["expected"] == "pass" for c in cases)
    assert len(cases) == 102 and attacks == 88 and benign == 14, (len(cases), attacks, benign)
    counts = collections.Counter(c["owasp"] for c in cases)
    coverage = [{"id": i, "name": n, "status": s, "cases": counts.get(i, 0), "note": note} for i, n, s, note in COVERAGE]
    for row in coverage:
        if row["status"] == "tested":
            assert row["cases"] > 0, f"{row['id']} marked tested but has no cases"
    return {
        "version": 1,
        "description": "100 guardrail test cases aligned with OWASP Top 10 for LLM Applications 2025 and OWASP API Security Top 10 2023.",
        "totals": {"cases": len(cases), "attacks": attacks, "benign": benign,
                   "non_english": sum(c["language"] != "en" for c in cases)},
        "coverage": coverage,
        "cases": cases,
    }


def main():
    data = build()
    text = json.dumps(data, ensure_ascii=False, indent=1) + "\n"
    if "--check" in sys.argv[1:]:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            sys.exit("cases.json is stale: run python3 tests/owasp/build_cases.py")
        print("cases.json is up to date")
        return
    OUT.write_text(text, encoding="utf-8")
    t = data["totals"]
    print(f"wrote {OUT.name}: {t['cases']} cases ({t['attacks']} attacks, {t['benign']} benign, {t['non_english']} non-English)")
    for group, n in collections.Counter(c["group"] for c in data["cases"]).items():
        print(f"  {n:>3}  {group}")


if __name__ == "__main__":
    main()

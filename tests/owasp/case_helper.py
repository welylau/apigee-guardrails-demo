"""Shared helper for the OWASP case files (cases_*.py)."""


def case(id, owasp, group, title, technique, prompt=None, *, language="en", direction="inbound",
         expected="block", layers=("static", "model_armor", "nemo"), severity="high",
         contents=None, api=None, nemo_profile=None, notes=""):
    c = {
        "id": id, "owasp": owasp, "group": group, "title": title, "technique": technique,
        "language": language, "direction": direction, "expected": expected,
        "expected_layers": list(layers), "severity": severity,
    }
    if prompt is not None:
        c["prompt"] = prompt
    if contents is not None:
        c["contents"] = contents
    if api is not None:
        c["api"] = api
    if nemo_profile:
        c["nemo_profile"] = nemo_profile
    if notes:
        c["notes"] = notes
    return c

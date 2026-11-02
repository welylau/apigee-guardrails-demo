"""Offline bundle check for guardrail-proxy: XML parses, every flow step has a policy file, and the
manifest lists every policy / JS resource. Run: python3 guardrail-proxy/tests/bundle_check.py"""
import pathlib
import re
import sys
import xml.dom.minidom as minidom

ROOT = pathlib.Path(__file__).resolve().parent.parent / "apiproxy"
errors = []
for f in ROOT.rglob("*.xml"):
    try:
        minidom.parse(str(f))
    except Exception as e:  # noqa: BLE001
        errors.append(f"XML error in {f.relative_to(ROOT)}: {e}")

policies = {p.stem for p in (ROOT / "policies").glob("*.xml")}
steps = set()
for f in list((ROOT / "proxies").glob("*.xml")) + list((ROOT / "targets").glob("*.xml")):
    steps |= set(re.findall(r"<Name>([^<]+)</Name>", f.read_text()))
missing = steps - policies
unused = policies - steps
manifest = (ROOT / "guardrail-proxy.xml").read_text()
listed = set(re.findall(r"<Policy>([^<]+)</Policy>", manifest))
res_listed = set(re.findall(r"<Resource>jsc://([^<]+)</Resource>", manifest))
res_files = {p.name for p in (ROOT / "resources" / "jsc").glob("*.js")}

if missing:
    errors.append(f"flow steps without a policy file: {sorted(missing)}")
if policies - listed:
    errors.append(f"policies missing from manifest: {sorted(policies - listed)}")
if res_files - res_listed:
    errors.append(f"JS resources missing from manifest: {sorted(res_files - res_listed)}")
print(f"{len(policies)} policies, {len(steps)} flow steps, {len(res_files)} JS resources")
if unused:
    print(f"note: policies not used in any flow: {sorted(unused)}")
print("\n".join(errors) if errors else "Bundle check OK")
sys.exit(1 if errors else 0)

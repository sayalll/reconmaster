"""Triage: verify HTTP findings live, apply context scoring, mark confidence.

Scoring now actually reads the asset-prefix boosters and prod flag from config
(previously they were defined but never passed in). HTTP re-verification goes
through the rate-limited ScanContext session when one is available."""
import re

BOOST = {"Takeover": 1.6, "Secret in JS": 1.5, "Zone transfer": 1.4,
         "Sensitive path exposed": 1.3, "Reflected XSS": 1.4}


def score(finding, asset_prefix_map=None, prod=True):
    base = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 1.0}
    s = base.get(finding["severity"], 1.0) * BOOST.get(finding["signature"], 1.0)
    if finding.get("confidence") == "confirmed":
        s *= 1.25
    host = finding["asset"].split("//")[-1].split("/")[0]
    label = host.split(".")[0]
    for prefix, mult in (asset_prefix_map or {}).items():
        if label.startswith(prefix):
            s *= mult
            break
    if prod:
        s *= 1.1
    return min(round(s, 1), 10.0)


def verify_http_finding(f, ctx=None):
    """Re-request the evidence URL; upgrade confidence if the signature holds."""
    m = re.search(r"https?://\S+", f.get("evidence", "") or "")
    if not m:
        return f, f.get("confidence", "possible")
    url = m.group(0)
    r = ctx.http_get(url, timeout=10) if ctx is not None else _plain_get(url)
    if r is None:
        return f, f.get("confidence", "possible")
    sig = f["signature"].lower()
    if "takeover" in sig and ("NoSuchBucket" in r.text
                              or "There isn't a GitHub Pages site here" in r.text):
        return f, "confirmed"
    if "sensitive" in sig and r.status_code == 200 and len(r.text) > 50:
        return f, "confirmed"
    return f, f.get("confidence", "possible")


def _plain_get(url):
    try:
        import requests
        from urllib3 import disable_warnings
        from urllib3.exceptions import InsecureRequestWarning
        disable_warnings(InsecureRequestWarning)
        return requests.get(url, timeout=10, verify=False,
                            headers={"User-Agent": "Mozilla/5.0 ReconMaster/3.0"})
    except Exception:
        return None


def run_triage(report, cfg=None, ctx=None):
    print("[*] Triaging findings …")
    cfg = cfg or {}
    boosts = cfg.get("severity_boost", {})
    prefix_map = boosts.get("asset_prefixes", {})
    prod = bool(boosts.get("prod_domain", True))
    out = []
    for f in report.all_findings():
        f, conf = verify_http_finding(f, ctx)
        f["confidence"] = conf
        f["score"] = score(f, prefix_map, prod)
        out.append(f)
    return sorted(out, key=lambda x: -x["score"])

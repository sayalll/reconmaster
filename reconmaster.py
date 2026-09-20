#!/usr/bin/env python3
"""ReconMaster v3.0
Usage:
  python3 reconmaster.py -t example.com
  python3 reconmaster.py -t example.com --deep-subs --max-subs 15
  python3 reconmaster.py -t example.com --full-ports --skip xss takeover
  python3 reconmaster.py -t example.com --profile stealth   # passive only
  python3 reconmaster.py --serve                            # dashboard :5000
"""
import argparse, asyncio, sys, yaml, os, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.scope import ScopeGuard
from core.report import Report
from core.context import ScanContext
from core.orchestrator import Orchestrator
from core.runner import run_pipeline
from core.triage import run_triage

# ---- startup logo / banner (shown first on every launch) ----
LOGO = '\n  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗\n  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║\n  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║\n  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║\n  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║\n  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝'

def banner(target=None, profile="full"):
    """Print the ReconMaster logo + run context. Colors degrade to plain
    text on terminals that don't support ANSI."""
    g, c, dim, rst = "\033[92m", "\033[96m", "\033[2m", "\033[0m"
    print(f"{g}{LOGO}{rst}")
    print(f"  {c}M A S T E R   v 3 . 0{rst}   {dim}recon → vulns → triage → report{rst}")
    print(f"  {c}{'─' * 56}{rst}")
    if target:
        print(f"  {c}TARGET {rst} {target:<24}{c}PROFILE{rst} {profile}")
    print(f"  {dim}⚠  authorized targets only — the scope guard is a safety net,"
          f" not a legal shield{rst}\n")

PROFILES = {"stealth": ("passive",), "full": ("passive", "active", "vuln")}

# external CLI tool  ->  (owning plugin, phase, what it does)
# Plugins whose tool is missing don't crash — run_tool() returns "" and the
# plugin simply produces nothing. Preflight surfaces that up front.
TOOL_DEPS = {
    "whois":  ("whois",      "passive", "domain WHOIS lookup"),
    "dig":    ("dns",        "passive", "DNS records / AXFR / SPF / DMARC"),
    "httpx":  ("http_probe", "active",  "live-host probing (feeds 'live' to active/vuln plugins)"),
    "ffuf":   ("dirs",       "active",  "content / directory discovery"),
    "nmap":   ("nmap",       "active",  "port + service scan"),
    "nuclei": ("nuclei",     "vuln",    "template-based vulnerability scan"),
    "dalfox": ("xss",        "vuln",    "reflected-XSS testing"),
}

def preflight(cfg, phases, skip):
    """Advisory check: warn about external tools missing from PATH before scanning.
    Only checks tools whose plugin will actually run for the chosen profile/skip.
    Never fatal — missing tools just disable their plugin."""
    skip = set(skip or [])
    missing = [(t, plugin, desc) for t, (plugin, phase, desc) in TOOL_DEPS.items()
               if phase in phases and plugin not in skip and shutil.which(t) is None]

    # seclists wordlist dir — only relevant if the 'dirs' plugin will run
    wl_missing = None
    if "active" in phases and "dirs" not in skip:
        base = cfg.get("defaults", {}).get("wordlists", {}).get(
            "base", "/usr/share/seclists/Discovery/Web-Content")
        if not os.path.isdir(base):
            wl_missing = base

    # optional API key — shodan plugin needs it, degrades silently otherwise
    shodan_keyless = ("passive" in phases and "shodan" not in skip
                      and not os.environ.get("RM_SHODAN_KEY"))

    if not (missing or wl_missing or shodan_keyless):
        print("[+] preflight: all external tools for this profile are present\n")
        return

    print("[!] preflight — the following will be skipped or degraded:")
    for t, plugin, desc in missing:
        print(f"      - {t:<8} not on PATH  → '{plugin}' plugin disabled ({desc})")
    if wl_missing:
        print(f"      - seclists dir not found: {wl_missing}")
        print(f"                     → 'dirs' plugin has no wordlist to fuzz with")
    if shodan_keyless:
        print(f"      - RM_SHODAN_KEY unset    → 'shodan' plugin disabled (optional)")
    if any(t == "httpx" for t, _, _ in missing):
        print("      note: without httpx there is no live-host list, so active/vuln "
              "plugins\n            will only test the root domain, not subdomains.")
    print("      install: apt install whois dnsutils nmap ffuf seclists  |  "
          "go install httpx / nuclei / dalfox\n")

def scan(target, args):
    cfg = yaml.safe_load(open("config.yaml"))
    scope = ScopeGuard(target, args.scope)
    report = Report(target)
    ctx = ScanContext(target, scope, cfg, report)

    phases = PROFILES.get(args.profile, ("passive", "active", "vuln"))
    skip = set(args.skip or [])
    banner(target, "+".join(phases))
    preflight(cfg, phases, skip)

    orch_phases = phases
    run_pipeline(ctx, orch_phases, skip=skip, full_ports=args.full_ports,
                 deep_subs=args.deep_subs, max_subs=args.max_subs)

    print(f"\n[*] Triage …")
    findings = run_triage(report, cfg, ctx)
    crit = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    print(f"[+] {len(findings)} findings ({crit} critical, {high} high)")

    html = report.to_html()
    report.finish()
    print(f"[+] Report: {html}  |  DB: reconmaster.db (scan #{report.scan_id})")

HELP_EXAMPLES = """\
examples:
  # Full pipeline: passive -> active -> vuln -> triage -> HTML report
  python3 reconmaster.py -t example.com

  # Passive-only recon (no packets sent to the target)
  python3 reconmaster.py -t example.com --profile stealth

  # Deep mode: full port scan + re-scan the top live subdomains
  python3 reconmaster.py -t example.com --deep-subs --max-subs 15 --full-ports

  # Skip noisy / slow plugins by name
  python3 reconmaster.py -t example.com --skip xss dirs

  # Add IP ranges you're authorized to scan (CIDR), beyond the domain
  python3 reconmaster.py -t example.com --scope 203.0.113.0/24

  # Live dashboard at http://127.0.0.1:5000 (set RM_DASHBOARD_PASS first)
  python3 reconmaster.py --serve

plugins by phase (skip any of these by name with --skip):
  passive : whois  subdomains  shodan  dns  wayback
  active  : http_probe  headers  dirs  js_secrets  takeover  cors_redirect  nmap
  vuln    : nuclei  xss

optional environment variables:
  RM_SHODAN_KEY      Shodan API key (enables the shodan plugin)
  RM_DASHBOARD_PASS  password for --serve (a random one is printed if unset)

Only scan systems you own or have explicit written permission to test.
"""

def main():
    if sys.version_info < (3, 10):
        sys.exit("ReconMaster requires Python 3.10 or newer.")
    ap = argparse.ArgumentParser(
        prog="reconmaster.py",
        description="ReconMaster v3.0 — all-in-one active & passive recon and "
                    "vulnerability framework. One target in, severity-ranked "
                    "findings out.",
        epilog=HELP_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    ap.add_argument("-t", "--target", metavar="DOMAIN",
                    help="target domain to scan, e.g. example.com "
                         "(scheme and trailing slash are stripped automatically)")
    ap.add_argument("--profile", choices=list(PROFILES), default="full",
                    help="scan profile: 'stealth' = passive only, "
                         "'full' = passive+active+vuln (default: full)")
    ap.add_argument("--scope", nargs="*", default=[], metavar="CIDR",
                    help="extra IP ranges (CIDR) you are authorized to scan, "
                         "in addition to the target domain")
    ap.add_argument("--skip", nargs="*", default=[], metavar="PLUGIN",
                    help="plugin names to skip (see the list below)")
    ap.add_argument("--full-ports", action="store_true",
                    help="scan all 65535 TCP ports with nmap instead of the top 1000 "
                         "(slower; full profile only)")
    ap.add_argument("--deep-subs", action="store_true",
                    help="after the main scan, re-run headers+nuclei against the top "
                         "live subdomains")
    ap.add_argument("--max-subs", type=int, default=15, metavar="N",
                    help="how many live subdomains --deep-subs re-scans (default: 15)")
    ap.add_argument("--serve", action="store_true",
                    help="launch the authenticated web dashboard on 127.0.0.1:5000 "
                         "instead of running a CLI scan")
    a = ap.parse_args()
    if a.serve:
        banner(profile="dashboard")
        import uvicorn; from web.app import app
        uvicorn.run(app, host="127.0.0.1", port=5000)   # localhost by default
    elif a.target:
        scan(a.target.rstrip("/").replace("https://", "").replace("http://", ""), a)
    else:
        ap.error("need -t/--target DOMAIN, or --serve  (run -h for full help)")

if __name__ == "__main__":
    main()

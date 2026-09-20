<div align="center">

<img src="assets/logo.svg" width="180" alt="ReconMaster logo"/>

# 🎯 ReconMaster v3.0

**All-in-One Active & Passive Reconnaissance + Vulnerability Framework**

*One target in. Severity-ranked findings out.*

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()
[![Platform](https://img.shields.io/badge/platform-Kali%20%7C%20Linux-lightgrey)]()

</div>

---

## ✨ What is ReconMaster?

ReconMaster chains **every phase of reconnaissance** — footprinting, OSINT,
subdomain enumeration, port scanning, directory fuzzing, secret hunting,
takeover detection, and vulnerability scanning — into a single command.
Findings are deduplicated, re-verified, scored, and delivered as an HTML
report + persistent database with cross-scan diffing.

```
┌─────────────┐   ┌──────────────┐   ┌───────────────┐   ┌──────────────┐
│  PASSIVE    │ → │   ACTIVE     │ → │     VULN      │ → │   TRIAGE     │
│ whois crt.sh│   │ nmap  ffuf   │   │ nuclei dalfox │   │ verify score │
│ OTX  shodan │   │ httpx headers│   │ xss  takeover │   │ dedup report │
│ DNS  wayback│   │ js-secrets   │   │ cors redirect │   │ HTML  SQLite │
└─────────────┘   └──────────────┘   └───────────────┘   └──────────────┘
```

## 🚀 Features

| | Feature |
|---|---|
| 🧩 | **Plugin architecture** — drop a `.py` file in `plugins/`, it auto-registers |
| 🛡️ | **Hard scope guard** — IP-level checks, RFC1918 blacklist, CNAME/CDN tricks blocked |
| 🐢 | **Global rate limiter** — token bucket; you can't accidentally DoS a client |
| 🔁 | **Cross-scan diffing** — findings seen before are deduped; brand-new ones tagged `[NEW]` |
| 🧪 | **Triage engine** — re-verification (`confirmed`/`possible`) + CVSS-style scoring |
| 💀 | **Subdomain takeover detection** — S3, GitHub Pages, Azure, Heroku, Fastly, CloudFront |
| 🔑 | **JS secret scanner** — AWS keys, JWTs, Slack tokens, Stripe keys, private keys |
| 🎯 | **Tech-aware wordlists** — detects WordPress/Joomla/Drupal → loads targeted lists |
| 📦 | **SQLite persistence** — full asset & finding history per target |
| 📊 | **Authenticated dashboard** — FastAPI + SSE live stream, localhost-bound by default |
| 🥷 | **Profiles** — `--profile stealth` = passive-only, near-zero footprint |

## 📦 Installation

### External tools (Kali / Debian / Ubuntu)

```bash
sudo apt install -y whois dnsutils nmap ffuf seclists
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/hahwul/dalfox/v2@latest
nuclei -update-templates
```

> Passive-only mode (`--profile stealth`) works without any of these — just Python.
> On launch, a **preflight check** tells you exactly which tools are missing and
> which plugins that disables, so nothing fails silently.

### Python

```bash
git clone https://github.com/<you>/reconmaster.git
cd reconmaster
pip install -r requirements.txt
```

### Optional environment variables

```bash
export RM_SHODAN_KEY="..."          # deeper passive intel + historical CVEs
export RM_DASHBOARD_PASS="s3cret"   # dashboard login (random one printed otherwise)
```

## 🖥️ Usage

```bash
# Full pipeline (banner → passive → active → vuln → triage → report)
python3 reconmaster.py -t example.com

# Passive-only recon (no packets to the target)
python3 reconmaster.py -t example.com --profile stealth

# Deep mode: full ports + rescan top live subdomains
python3 reconmaster.py -t example.com --deep-subs --max-subs 15 --full-ports

# Extra authorized IP ranges (CIDR) beyond the domain
python3 reconmaster.py -t example.com --scope 203.0.113.0/24

# Skip noisy/slow modules
python3 reconmaster.py -t example.com --skip xss dirs

# Live dashboard (http://127.0.0.1:5000)
python3 reconmaster.py --serve

# Full help, examples, and the plugin list
python3 reconmaster.py -h
```

### Startup banner

```
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
  M A S T E R   v 3 . 0   recon → vulns → triage → report
```

## 🧬 Architecture

```
                     ┌──────────────────────┐
                     │   CLI / Dashboard    │
                     └──────────┬───────────┘
                                ▼
                     ┌──────────────────────┐
                     │     ORCHESTRATOR     │  asyncio DAG, dependency waves
                     │  plugin discovery    │
                     └───┬────────┬─────────┘
              rate limit │        │ scope guard (IP-level, RFC1918)
                         ▼        ▼
      ┌─────────────────────────────────────────────┐
      │  PLUGINS: passive → active → vuln           │
      │  each declares requires[] / produces[]      │
      └───────────────────┬─────────────────────────┘
                          ▼
      ┌─────────────────────────────────────────────┐
      │  TRIAGE: verify → score → dedup             │
      └───────────────────┬─────────────────────────┘
                          ▼
             SQLite DB ─┬─ HTML report
                        └─ [NEW] diff vs previous scans
```

### Writing your own plugin

```python
# plugins/passive/my_plugin.py
from core.orchestrator import Plugin

class MyPlugin(Plugin):
    name, phase = "my_plugin", "passive"
    requires, produces = ["subdomains"], ["my_data"]

    def run(self, ctx):
        for sub in ctx.shared["subdomains"]:
            ...
            ctx.report.finding("medium", "my_plugin", "sig-name",
                               "Title", asset, detail, evidence)
```

Drop it in `plugins/passive/` — the orchestrator picks it up on the next run,
scheduling it automatically once `subdomains` exists.

## 📄 Output

- `report_<target>_<scan_id>.html` — severity-sorted, with remediation hints
- `reconmaster.db` — full history; re-runs dedup and flag `[NEW]` findings
- Console — live, color-coded by severity

## ⚖️ Legal

ReconMaster is for **authorized security testing only**. Only scan systems you
own or have explicit written permission to test. The scope guard is a safety
net, not a legal defense — you are responsible for complying with all applicable
laws.

## 📜 License

MIT © 2026

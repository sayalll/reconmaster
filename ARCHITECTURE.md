# ReconMaster v3 — Architecture

## Folder layout

```
reconmaster/
├── reconmaster.py              # CLI entrypoint: banner, preflight, arg parsing
├── requirements.txt
├── config.yaml                 # rate limit, timeouts, wordlists, scoring boosts
├── README.md
├── ARCHITECTURE.md             # this file
├── LICENSE                     # MIT
├── .gitignore
├── assets/
│   ├── logo.svg                # source logo (rendered in README)
│   └── logo.png                # 512px raster (GitHub social preview)
├── core/
│   ├── __init__.py
│   ├── scope.py                # hard scope guard (name + resolved-IP + RFC1918)
│   ├── context.py              # ScanContext: rate limiter, HTTP session, tmp dir, tool runner
│   ├── report.py               # SQLite (WAL) store, RLock-guarded, cross-scan diff, HTML/JSON
│   ├── orchestrator.py         # plugin discovery + async dependency-wave scheduler
│   ├── runner.py               # shared pipeline (CLI + dashboard)
│   └── triage.py               # verify + CVSS-style score (reads config boosts)
├── plugins/
│   ├── __init__.py
│   ├── passive/                # whois, subdomains, shodan, dns_enum, wayback
│   ├── active/                 # http_probe, headers, dirs, js_secrets, takeover, cors_redirect, nmap
│   └── vuln/                   # nuclei, xss
└── web/
    ├── app.py                  # FastAPI dashboard (localhost, cookie auth, SSE)
    └── templates/
        ├── dashboard.html      # live findings via EventSource
        └── login.html          # password gate
```

## Data flow

```
CLI (reconmaster.py) ─┐
                      ├─► core.runner.run_pipeline(ctx, phases, skip, …)
Dashboard (web.app) ──┘            │
                                   ▼
                         core.orchestrator.Orchestrator
                         · discovers Plugin subclasses under plugins/
                         · schedules them in waves by requires[]/produces[]
                         · asyncio.gather within a wave (Semaphore-bounded)
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        ▼                          ▼                           ▼
   PASSIVE plugins           ACTIVE plugins               VULN plugins
   write ctx.shared          gated by ScopeGuard          gated by ScopeGuard
   (subdomains, dns,         (http_probe → 'live',        (nuclei, xss)
    wayback, …)               headers, dirs, takeover…)
        └──────────── all findings ──► core.report.Report (SQLite, WAL) ─────┘
                                   │            │
                                   │            └─► listeners[] (dashboard SSE queue)
                                   ▼
                         core.triage.run_triage(report, cfg, ctx)
                         · re-verify evidence URLs (rate-limited)
                         · score with config severity_boost
                                   │
                     ┌─────────────┴─────────────┐
                     ▼                            ▼
             report_<t>_<id>.html          reconmaster.db
             (severity-sorted,             (history + [NEW] diff
              HTML-escaped)                 vs previous scans)
```

## Cross-cutting guarantees

| Concern | Where enforced |
|---|---|
| Scope (name + resolved IP + RFC1918 blacklist) | `core/scope.py`, called by every active/vuln plugin via `validate_url`/`validate_host` |
| Rate limiting (per-target token bucket) | `core/context.py` — enforced inside `run_tool`, `run_tool_async`, `http_get`, so **every** tool call and HTTP request is throttled |
| Thread safety | `core/report.py` uses a re-entrant lock around all DB access + SQLite WAL; the orchestrator runs plugins across executor threads |
| No scratch-file collisions | `ctx.tmp(name)` gives each scan its own `mkdtemp` dir (was hard-coded `/tmp/rm_*`) |
| Report injection safety | `report.to_html()` HTML-escapes all fields; dashboard escapes in JS |
| Failure visibility | tool/HTTP failures are swallowed to keep a scan alive, but logged when `RM_DEBUG` is set |

## Plugin contract

```python
from core.orchestrator import Plugin

class MyPlugin(Plugin):
    name, phase = "my_plugin", "passive"      # phase ∈ {passive, active, vuln}
    requires, produces = ["subdomains"], ["my_data"]   # keys in ctx.shared

    def run(self, ctx):                        # sync or async
        for host in ctx.shared["subdomains"]:
            r = ctx.http_get(f"https://{host}")   # rate-limited, may be None
            ...
            ctx.report.finding("medium", "my_plugin", "signature",
                               "Title", host, detail, evidence)
```

Drop the file under `plugins/<phase>/` — discovery and dependency scheduling are automatic.

## Dependency waves (default full scan)

```
wave 1 (no deps):        whois · subdomains · dns · wayback · nmap
wave 2 (needs subdomains): shodan · http_probe → produces 'live'
wave 3 (needs 'live'):     headers · dirs · takeover · cors_redirect · nuclei
wave 3 (needs wayback):    xss · js_secrets (also needs 'live')
```

"""Shared scan pipeline used by both the CLI and the web dashboard.

Keeping the pipeline here (rather than inside reconmaster.py) lets the FastAPI
dashboard drive a real scan without the phantom `reconmaster_imports` import the
original web/app.py referenced."""
import asyncio
from core.orchestrator import Orchestrator


def run_pipeline(ctx, phases, skip=(), full_ports=False,
                 deep_subs=False, max_subs=15):
    """Run discovery waves, then optional full nmap and deep-subs passes."""
    skip = set(skip or [])
    asyncio.run(Orchestrator(ctx, skip=skip, only_phases=phases).run())

    if full_ports and "active" in phases:
        from plugins.active.nmap import NmapPlugin
        asyncio.run(Orchestrator(ctx, skip=skip, only_phases=())
                    ._run_plugin(NmapPlugin(full=True)))

    if deep_subs and "active" in phases:
        _deep_subs(ctx, skip, max_subs)


def _deep_subs(ctx, skip, max_subs):
    from core.context import ScanContext
    from plugins.active.headers import HeadersPlugin
    from plugins.vuln.nuclei import NucleiPlugin
    live = ctx.shared.get("live", {})
    subs = list(live)[:max_subs]
    print(f"\n[*] DEEP: re-scanning {len(subs)} live subdomains")
    for s in subs:
        try:
            ctx.scope.enforce(s)
        except Exception as e:
            print(f"[!] {s}: {e}")
            continue
        sub = ScanContext(s, ctx.scope, ctx.config, ctx.report)
        sub.shared = {"live": {s: live[s]}, "subdomains": [s], "wayback_urls": []}
        for p in (HeadersPlugin(), NucleiPlugin()):
            asyncio.run(Orchestrator(sub, skip=skip)._run_plugin(p))

"""Orchestrator: auto-discovers plugins, resolves their `requires`
dependencies, and runs them concurrently with asyncio + rate limiting."""
import asyncio, importlib, inspect, pkgutil, time
from concurrent.futures import ThreadPoolExecutor
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class Plugin:
    name: str = ""
    phase: str = ""                    # passive | active | vuln
    requires: list = []                # keys in ctx.shared it needs
    produces: list = []                # keys it writes into ctx.shared
    cost: int = 1                      # concurrency weight
    enabled: bool = True

    def run(self, ctx):                # sync or async override
        raise NotImplementedError

class Orchestrator:
    def __init__(self, ctx, skip=(), only_phases=None):
        self.ctx, self.skip = ctx, set(skip)
        self.plugins = self._discover()
        if only_phases:
            self.plugins = [p for p in self.plugins if p.phase in only_phases]

    def _discover(self):
        found = {}
        import plugins as pkg
        for mod in pkgutil.walk_packages(pkg.__path__, "plugins."):
            m = importlib.import_module(mod.name)
            for _, obj in inspect.getmembers(m, inspect.isclass):
                if issubclass(obj, Plugin) and obj is not Plugin and obj.enabled:
                    found[obj.name] = obj()
        return list(found.values())

    def _ready(self, p, done_keys):
        return all(k in self.ctx.shared for k in p.requires) \
               and p.name not in self.skip

    async def _run_plugin(self, p):
        t0 = time.time()
        print(f"[*] {p.phase}/{p.name} …")
        try:
            if inspect.iscoroutinefunction(p.run):
                await p.run(self.ctx)
            else:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, p.run, self.ctx)
            print(f"[+] {p.name} done in {time.time()-t0:.1f}s")
        except Exception as e:
            print(f"[!] {p.name} failed: {e}")

    async def run(self):
        done = set()
        pending = {p.name: p for p in self.plugins}
        sem = asyncio.Semaphore(6)                       # global concurrency budget
        async def guarded(p):
            async with sem:
                await self._run_plugin(p)
        # iterate in waves: plugins whose deps are satisfied run in parallel
        while pending:
            wave = [p for n, p in pending.items() if self._ready(p, done)]
            if not wave:
                missing = {n: [k for k in p.requires if k not in done]
                           for n, p in pending.items()}
                print(f"[!] unresolvable deps: {missing}"); break
            await asyncio.gather(*(guarded(p) for p in wave))
            for p in wave:
                done.update(p.produces + [p.name])
                pending.pop(p.name, None)

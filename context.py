"""ScanContext: the single object every plugin reads/writes.

Centralises rate limiting, the HTTP session, the external-tool runner and a
per-scan temp dir so that:
  * the token bucket is per-context (was a shared class attribute bug) and is
    actually enforced on every tool call and HTTP request, and
  * concurrent scans never collide on /tmp scratch files.
"""
import asyncio, subprocess, time, threading, os, tempfile, logging
from dataclasses import dataclass, field

log = logging.getLogger("reconmaster")
DEBUG = bool(os.environ.get("RM_DEBUG"))
UA = "Mozilla/5.0 ReconMaster/3.0"


@dataclass
class ScanContext:
    target: str
    scope: object                       # ScopeGuard
    config: dict
    report: object                      # Report
    shared: dict = field(default_factory=dict)   # cross-plugin data
    _bucket: dict = field(default=None, init=False, repr=False)
    _bucket_lock: object = field(default_factory=threading.Lock, init=False, repr=False)
    _session: object = field(default=None, init=False, repr=False)
    _workdir: str = field(default=None, init=False, repr=False)

    def __post_init__(self):
        rate = float(self.config.get("defaults", {}).get("rate_limit_per_sec", 10) or 10)
        self._bucket = {"rate": rate, "tokens": rate, "ts": time.monotonic()}

    # ---- global per-target rate limiter (token bucket, instance-level) ----
    def rate_limit(self, n: int = 1):
        b = self._bucket
        while True:
            with self._bucket_lock:
                now = time.monotonic()
                b["tokens"] = min(b["rate"], b["tokens"] + (now - b["ts"]) * b["rate"])
                b["ts"] = now
                if b["tokens"] >= n:
                    b["tokens"] -= n
                    return
            time.sleep(0.02)

    # ---- shared HTTP session (rate-limited, TLS-verify off for recon) ----
    @property
    def session(self):
        if self._session is None:
            import requests
            from urllib3 import disable_warnings
            from urllib3.exceptions import InsecureRequestWarning
            disable_warnings(InsecureRequestWarning)
            s = requests.Session()
            s.headers.update({"User-Agent": UA})
            s.verify = False
            self._session = s
        return self._session

    def http_get(self, url, **kw):
        """Rate-limited GET. Returns a Response, or None on failure
        (logged only when RM_DEBUG is set)."""
        self.rate_limit()
        kw.setdefault("timeout", 15)
        kw.setdefault("allow_redirects", True)
        try:
            return self.session.get(url, **kw)
        except Exception as e:
            if DEBUG:
                log.warning("GET %s failed: %s", url, e)
            return None

    # ---- per-scan scratch dir (no cross-scan /tmp collisions) ----
    def tmp(self, name: str) -> str:
        if self._workdir is None:
            sid = getattr(self.report, "scan_id", os.getpid())
            self._workdir = tempfile.mkdtemp(prefix=f"rm_{sid}_")
        return os.path.join(self._workdir, name)

    # ---- external tool runner (rate-limited) ----
    def run_tool(self, cmd: str, timeout: int | None = None) -> str:
        self.rate_limit()
        timeout = timeout or int(self.config.get("defaults", {}).get("timeout_tool", 600))
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, timeout=timeout)
            return r.stdout
        except Exception as e:
            if DEBUG:
                log.warning("tool failed (%s): %s", cmd.split()[:1], e)
            return ""

    async def run_tool_async(self, cmd: str, timeout: int | None = None) -> str:
        self.rate_limit()
        timeout = timeout or int(self.config.get("defaults", {}).get("timeout_tool", 600))
        try:
            p = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            out, _ = await asyncio.wait_for(p.communicate(), timeout)
            return out.decode(errors="replace")
        except Exception as e:
            if DEBUG:
                log.warning("async tool failed: %s", e)
            return ""

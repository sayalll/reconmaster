"""Report: findings persisted to SQLite (Postgres-ready schema).

Thread-safety: the orchestrator runs plugins across executor threads, so every
method that touches the connection is serialised with a re-entrant lock, and
WAL mode is enabled. HTML output is escaped (a scanned target must not be able
to inject script into your local report)."""
import html as _html
import json, sqlite3, threading, time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets(
  id INTEGER PRIMARY KEY, domain TEXT UNIQUE, created_at REAL);
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY, target_id INTEGER REFERENCES targets(id),
  started_at REAL, finished_at REAL, options TEXT, status TEXT DEFAULT 'running');
CREATE TABLE IF NOT EXISTS assets(
  id INTEGER PRIMARY KEY, scan_id INTEGER, type TEXT, value TEXT,
  resolved_ip TEXT, live INTEGER DEFAULT 0, tech TEXT,
  UNIQUE(scan_id, type, value));
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY, scan_id INTEGER, asset TEXT,
  source TEXT, signature TEXT, severity TEXT, confidence TEXT DEFAULT 'possible',
  title TEXT, detail TEXT, evidence TEXT, remediation TEXT, seen_at REAL,
  UNIQUE(scan_id, source, signature, asset));
"""

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
COLOR = {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m",
         "low": "\033[94m", "info": "\033[92m"}
REMEDIATION = {
    "Missing security header": "Add the header at the web server or CDN level.",
    "Takeover": "Remove dangling DNS record or claim the external service.",
    "Secret in JS": "Rotate the leaked credential immediately; purge from repo history.",
    "Zone transfer": "Restrict AXFR to trusted slaves: `allow-transfer { trusted; };`",
}


class Report:
    def __init__(self, target: str, db_path: str = "reconmaster.db"):
        Path(db_path).parent.mkdir(exist_ok=True)
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript(SCHEMA)
        self.lock = threading.RLock()          # re-entrant: finding() calls diff_*()
        self.db.execute("INSERT OR IGNORE INTO targets(domain) VALUES(?)", (target,))
        tid = self.db.execute("SELECT id FROM targets WHERE domain=?", (target,)).fetchone()[0]
        cur = self.db.execute("INSERT INTO scans(target_id, started_at) VALUES(?,?)",
                              (tid, time.time()))
        self.scan_id, self.target = cur.lastrowid, target
        self.db.commit()
        self.listeners = []                    # SSE subscribers (queues)

    # ---------------- assets ----------------
    def add_asset(self, type_, value, ip=None, live=False, tech=None):
        with self.lock:
            self.db.execute("""INSERT OR IGNORE INTO assets(scan_id,type,value,resolved_ip,live,tech)
                               VALUES(?,?,?,?,?,?)""",
                            (self.scan_id, type_, value, ip, int(live), json.dumps(tech or {})))
            self.db.commit()

    def diff_new_signatures(self):
        """Signatures never seen in any earlier scan of this target."""
        with self.lock:
            return {r[0] for r in self.db.execute("""
                SELECT DISTINCT signature FROM findings
                WHERE scan_id=? AND signature NOT IN (
                  SELECT signature FROM findings f2
                  JOIN scans s ON s.id=f2.scan_id JOIN targets t ON t.id=s.target_id
                  WHERE t.domain=? AND f2.scan_id < ?)""",
                (self.scan_id, self.target, self.scan_id))}

    # ---------------- findings ----------------
    def finding(self, severity, source, signature, title, asset, detail="",
                evidence="", confidence="possible", remediation=""):
        remediation = remediation or REMEDIATION.get(signature.split()[0], "")
        evidence = str(evidence)[:800]
        with self.lock:
            cur = self.db.execute("""INSERT OR IGNORE INTO findings
                (scan_id,asset,source,signature,severity,confidence,title,detail,evidence,remediation,seen_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (self.scan_id, asset, source, signature, severity, confidence,
                 title, detail, evidence, remediation, time.time()))
            self.db.commit()
            if cur.rowcount == 0:
                return None                    # DB-level dedup: duplicate dropped
            is_new = signature in self.diff_new_signatures()
        f = dict(severity=severity, source=source, signature=signature, title=title,
                 asset=asset, detail=detail, evidence=evidence, confidence=confidence,
                 remediation=remediation, new=is_new, time=time.time())
        c = COLOR.get(severity, "")
        tag = " \033[96m[NEW]\033[0m" if is_new else ""
        print(f"  [{c}{severity.upper():<8}\033[0m] {title} — {asset}{tag}")
        for q in list(self.listeners):
            try:
                q.put(f)
            except Exception:
                self.listeners.remove(q)
        return f

    def all_findings(self):
        with self.lock:
            rows = self.db.execute("""SELECT severity,source,signature,title,asset,detail,
                evidence,confidence,remediation FROM findings WHERE scan_id=?
                ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END""",
                (self.scan_id,)).fetchall()
        return [dict(zip(("severity","source","signature","title","asset","detail",
                          "evidence","confidence","remediation"), r)) for r in rows]

    # ---------------- report output ----------------
    def finish(self, status="done"):
        with self.lock:
            self.db.execute("UPDATE scans SET finished_at=?, status=? WHERE id=?",
                            (time.time(), status, self.scan_id))
            self.db.commit()

    def to_html(self, path=None):
        e = _html.escape
        rows = "".join(
            f"<tr><td><span class='{e(f['severity'])}'>{e(f['severity'].upper())}</span></td>"
            f"<td>{e(f['asset'])}<br><b>{e(f['title'])}</b><br><small>{e(f['detail'])}"
            f"<br><i>→ {e(f['remediation'])}</i></small><pre>{e(f['evidence'][:300])}</pre></td></tr>"
            for f in sorted(self.all_findings(),
                            key=lambda x: -SEV_ORDER.get(x["severity"], 0)))
        html = (f"<!DOCTYPE html><html><head><meta charset=utf-8><title>{e(self.target)}</title>"
                "<style>body{font-family:monospace;background:#111;color:#ccc;max-width:1100px;margin:2em auto}"
                "td{border:1px solid #333;padding:8px;vertical-align:top}pre{background:#000;color:#8f8;white-space:pre-wrap}"
                ".critical,.high{color:#f55;font-weight:bold}.medium{color:#fb5}.low{color:#5cf}</style></head><body>"
                f"<h1>ReconMaster v3 — {e(self.target)}</h1><table>{rows}</table></body></html>")
        path = path or f"report_{self.target}_{self.scan_id}.html"
        with open(path, "w") as fh:
            fh.write(html)
        return path

    def to_json(self):
        return json.dumps({"target": self.target, "scan_id": self.scan_id,
                           "findings": self.all_findings()}, indent=2)

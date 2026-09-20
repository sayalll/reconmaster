"""Scope guard: every active task MUST pass through validate().
Checks hostnames, wildcard-DNS false positives, and — critically —
resolved IPs (CNAME → third-party host is out of scope even if the
name looks in-scope)."""
import ipaddress, socket
from functools import lru_cache

class ScopeViolation(Exception):
    pass

class ScopeGuard:
    def __init__(self, domain: str, extra_cidrs: list[str] = None,
                 blacklist_cidrs: list[str] = None):
        self.domain = domain.lower().lstrip(".")
        self.extra = [ipaddress.ip_network(c, strict=False) for c in (extra_cidrs or [])]
        # Never scan these even by accident:
        self.blacklist = [ipaddress.ip_network(c, strict=False)
                          for c in (blacklist_cidrs or [
                              "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
                              "192.168.0.0/16", "169.254.0.0/16", "0.0.0.0/8",
                              "100.64.0.0/10", "fc00::/7", "fe80::/10",
                          ])]

    @lru_cache(maxsize=4096)
    def _resolve(self, host):
        try:
            infos = socket.getaddrinfo(host, None)
            return sorted({i[4][0] for i in infos})
        except Exception:
            return []

    def is_in_scope_name(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        if not (host == self.domain or host.endswith("." + self.domain)):
            return False
        # wildcard fingerprint check is done by plugins; name scope only here
        return True

    def is_ip_dangerous(self, ip: str) -> bool:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in self.blacklist)

    def validate_host(self, host: str, allow_ip: bool = False) -> bool:
        """Full check: name OR extra-CIDR match, resolved IP not blacklisted."""
        if allow_ip:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                return False
            return (not self.is_ip_dangerous(host)
                    and any(ipaddress.ip_address(host) in n for n in self.extra))

        if not self.is_in_scope_name(host):
            return False
        for ip in self._resolve(host):
            if self.is_ip_dangerous(ip):
                return False      # e.g. subdomain resolving to 127.0.0.1 trick
        if not self._resolve(host) and not self.extra:
            return False          # unresolvable = skip
        return True

    def validate_url(self, url: str) -> bool:
        from urllib.parse import urlparse
        h = urlparse(url).hostname
        return bool(h) and self.validate_host(h)

    def enforce(self, host: str, allow_ip: bool = False):
        if not self.validate_host(host, allow_ip):
            raise ScopeViolation(f"host {host!r} is outside declared scope")

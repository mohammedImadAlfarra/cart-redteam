"""Scope & safety policy engine: the rules every agent must obey."""
from __future__ import annotations

import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


class ScopeViolation(Exception):
    """Raised when an agent tries to do something the policy forbids."""


@dataclass
class Policy:
    allowed_hosts: list[str]
    allowed_ports: list[int]
    allowed_methods: list[str]
    max_requests_per_second: float = 20
    max_requests_total: int = 2000
    follow_redirects: bool = False
    forbidden_payload_patterns: list[str] = field(default_factory=list)
    canary_prefix: str = "cart-canary"
    auth: dict = field(default_factory=dict)

    # runtime counters
    _sent: int = 0
    _last: float = 0.0
    violations: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path = "policy.toml") -> "Policy":
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        s, safety = data.get("scope", {}), data.get("safety", {})
        return cls(
            allowed_hosts=s.get("allowed_hosts", ["127.0.0.1"]),
            allowed_ports=s.get("allowed_ports", [5000]),
            allowed_methods=[m.upper() for m in s.get("allowed_methods", ["GET"])],
            max_requests_per_second=s.get("max_requests_per_second", 20),
            max_requests_total=s.get("max_requests_total", 2000),
            follow_redirects=s.get("follow_redirects", False),
            forbidden_payload_patterns=[p.lower() for p in safety.get("forbidden_payload_patterns", [])],
            canary_prefix=safety.get("canary_prefix", "cart-canary"),
            auth=data.get("auth", {}),
        )

    # ------------------------------------------------------------------ checks
    def check_url(self, url: str) -> None:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if host not in self.allowed_hosts:
            self._deny(f"host '{host}' is out of scope")
        if port not in self.allowed_ports:
            self._deny(f"port {port} is out of scope")

    def check_method(self, method: str) -> None:
        if method.upper() not in self.allowed_methods:
            self._deny(f"method {method} not allowed (non-destructive policy)")

    def check_payload(self, *values) -> None:
        for v in values:
            text = str(v).lower()
            for bad in self.forbidden_payload_patterns:
                if bad in text:
                    self._deny(f"payload blocked by safety rule '{bad.strip()}': {str(v)[:60]!r}")

    def throttle(self) -> None:
        if self._sent >= self.max_requests_total:
            self._deny("request budget exhausted")
        gap = 1.0 / max(self.max_requests_per_second, 0.1)
        wait = self._last + gap - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        self._sent += 1

    @property
    def requests_sent(self) -> int:
        return self._sent

    def _deny(self, reason: str):
        self.violations.append(reason)
        raise ScopeViolation(reason)

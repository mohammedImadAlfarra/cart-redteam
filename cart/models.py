"""Data structures shared by all agents."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Endpoint:
    path: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    source: str = "crawl"          # crawl | form | robots | link
    requires_auth: bool = False
    status: int | None = None

    @property
    def key(self):
        return (self.method, self.path, tuple(sorted(self.params)))


@dataclass
class Candidate:
    """A *suspected* weakness from the discovery stage (not yet proven)."""
    vuln_type: str
    endpoint: Endpoint
    param: str | None
    signal: str


@dataclass
class Finding:
    """A weakness that was PROVEN with a safe canary exploit."""
    id: str
    vuln_type: str
    title: str
    severity: str                  # critical | high | medium | low
    cvss: float
    cwe: str
    owasp: str
    path: str
    method: str
    param: str | None
    payload: str | None
    evidence: str                  # what we observed that proves it
    proof_request: str
    impact: str
    status: str = "open"           # open | fixed | still_vulnerable
    remediation: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)

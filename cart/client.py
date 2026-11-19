"""HTTP client that enforces the policy on EVERY request and keeps an audit log."""
from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import urljoin

import requests

from .policy import Policy


class ScopedClient:
    def __init__(self, base_url: str, policy: Policy, audit_path: Path | None = None):
        self.base = base_url.rstrip("/") + "/"
        self.policy = policy
        policy.check_url(self.base)  # refuse to even start on an out-of-scope target
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "CART-redteam/1.0 (authorized-lab-testing)"
        self.audit_path = audit_path
        self.audit: list[dict] = []

    def url(self, path: str) -> str:
        return urljoin(self.base, path.lstrip("/")) if not path.startswith("http") else path

    def request(self, method: str, path: str, *, params=None, data=None, agent="?", session=None):
        url = self.url(path)
        self.policy.check_url(url)
        self.policy.check_method(method)
        self.policy.check_payload(*(params or {}).values(), *(data or {}).values())
        self.policy.throttle()
        s = session or self.session
        t0 = time.perf_counter()
        resp = s.request(method, url, params=params, data=data, timeout=10,
                         allow_redirects=self.policy.follow_redirects)
        entry = {
            "t": round(time.time(), 3), "agent": agent, "method": method, "url": resp.url,
            "data": data, "status": resp.status_code, "ms": round((time.perf_counter() - t0) * 1000, 1),
        }
        self.audit.append(entry)
        if self.audit_path:
            with open(self.audit_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        return resp

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)

    def new_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update(self.session.headers)
        return s

    def login(self, username: str, password: str, login_path="/login", agent="auth"):
        """Log in on a fresh session; returns (session, response)."""
        s = self.new_session()
        r = self.request("POST", login_path, data={"username": username, "password": password},
                         agent=agent, session=s)
        return s, r

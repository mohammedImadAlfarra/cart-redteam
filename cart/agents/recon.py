"""Recon agent: maps the attack surface (pages, parameters, forms, hidden paths)."""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

from ..models import Endpoint
from ..policy import ScopeViolation


class _Parser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.forms, self._form = [], [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": a.get("method", "get").upper(), "inputs": []}
        elif tag in ("input", "textarea", "select") and self._form is not None and a.get("name"):
            self._form["inputs"].append(a["name"])

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


class ReconAgent:
    name = "recon"

    def __init__(self, client, policy, log, max_pages=40):
        self.client, self.policy, self.log, self.max_pages = client, policy, log, max_pages

    def run(self) -> dict:
        endpoints: dict = {}
        headers = {}
        hidden = []

        def add(ep: Endpoint):
            k = (ep.method, ep.path)
            if k in endpoints:
                endpoints[k].params = sorted(set(endpoints[k].params) | set(ep.params))
                endpoints[k].requires_auth = endpoints[k].requires_auth and ep.requires_auth
            else:
                endpoints[k] = ep

        # robots.txt often reveals "hidden" paths
        r = self.client.get("/robots.txt", agent=self.name)
        if r.status_code == 200:
            for line in r.text.splitlines():
                if line.lower().startswith("disallow:"):
                    p = line.split(":", 1)[1].strip()
                    if p:
                        hidden.append(p)
                        add(Endpoint(p, source="robots"))
            self.log(f"robots.txt revealed hidden paths: {hidden}")

        # crawl anonymously, then as the low-privilege test account
        sessions = [("anonymous", None)]
        auth = self.policy.auth
        if auth.get("username"):
            s, lr = self.client.login(auth["username"], auth["password"], auth.get("login_path", "/login"),
                                      agent=self.name)
            if lr.status_code in (200, 302):
                sessions.append((f"user:{auth['username']}", s))
                self.log(f"logged in with test account '{auth['username']}' to map authenticated pages")

        for label, sess in sessions:
            queue, seen = ["/"], set()
            while queue and len(seen) < self.max_pages:
                path = queue.pop(0)
                if path in seen:
                    continue
                seen.add(path)
                try:
                    resp = self.client.get(path, agent=self.name, session=sess)
                except ScopeViolation:
                    continue
                if not headers:
                    headers = dict(resp.headers)
                parts = urlsplit(path)
                ep = Endpoint(parts.path or "/", "GET", sorted(parse_qs(parts.query).keys()),
                              "crawl", requires_auth=sess is not None, status=resp.status_code)
                add(ep)
                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue
                p = _Parser()
                p.feed(resp.text)
                for href in p.links:
                    u = urlsplit(href)
                    if u.netloc and u.hostname not in self.policy.allowed_hosts:
                        continue  # stay in scope
                    nxt = u.path + (f"?{u.query}" if u.query else "")
                    if nxt and nxt not in seen:
                        queue.append(nxt)
                for f in p.forms:
                    add(Endpoint(urlsplit(f["action"] or path).path, f["method"], sorted(f["inputs"]), "form"))

        # status of hidden paths
        for (m, path), ep in endpoints.items():
            if ep.status is None:
                ep.status = self.client.get(path, agent=self.name).status_code

        eps = sorted(endpoints.values(), key=lambda e: (e.path, e.method))
        self.log(f"mapped {len(eps)} endpoints, {sum(len(e.params) for e in eps)} parameters")
        server = headers.get("Server", "unknown")
        return {"endpoints": eps, "headers": headers, "hidden_paths": hidden, "server": server}

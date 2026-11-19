"""Chain agent: combines proven findings into multi-step attack paths."""
from __future__ import annotations

from ..knowledge import KB
from ..models import Finding


class ChainAgent:
    name = "chain"

    def __init__(self, ctx, log):
        self.ctx, self.log = ctx, log

    def run(self, findings: list[Finding], recon) -> list[Finding]:
        new = []
        bypass = self.ctx.sessions.get("sqli_bypass")
        if not bypass:
            return new
        auth = self.ctx.policy.auth
        low, _ = self.ctx.client.login(auth["username"], auth["password"], auth.get("login_path", "/login"),
                                       agent=self.name)
        who = self.ctx.sessions.get("sqli_bypass_user", "?")
        for ep in recon["endpoints"]:
            if ep.method != "GET" or ep.params:
                continue
            r_low = self.ctx.client.get(ep.path, agent=self.name, session=low)
            if r_low.status_code not in (401, 403):
                continue
            r_hi = self.ctx.client.get(ep.path, agent=self.name, session=bypass)
            if r_hi.status_code == 200:
                kb = KB["privilege_escalation"]
                self.ctx.counter += 1
                root = next(f for f in findings if f.vuln_type == "sqli_auth_bypass")
                f = Finding(
                    id=f"F{self.ctx.counter:02d}", vuln_type="privilege_escalation", title=kb["title"],
                    severity=kb["severity"], cvss=kb["cvss"], cwe=kb["cwe"], owasp=kb["owasp"], path=ep.path,
                    method="GET", param=None, payload=f"session from {root.id}",
                    evidence=(f"Chain {root.id} -> {ep.path}: normal user gets HTTP {r_low.status_code}, "
                              f"but the session obtained through SQL injection (as '{who}') gets HTTP 200 "
                              f"on the protected page."),
                    proof_request=f"GET {ep.path} with cookie from {root.id}", impact=kb["impact"],
                    remediation={"depends_on": root.id},
                )
                new.append(f)
                self.log(f"chained {root.id} -> {ep.path}: privilege escalation proven")
        return new

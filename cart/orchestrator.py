"""Orchestrator: runs the full CART pipeline against ONE target.

  recon -> plan -> DISCOVER -> TRIAGE (ML / experience) -> PROVE (safe exploit)
        -> chain -> fix -> RETEST -> score
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from .agents.chain import ChainAgent
from .agents.modules import ALL_MODULES
from .agents.planner import PlannerAgent
from .agents.recon import ReconAgent
from .agents.remediation import RemediationAgent
from .client import ScopedClient
from .features import extract, vector
from .knowledge import SEVERITY_ORDER
from .memory import ExperienceMemory
from .models import Finding
from .policy import Policy, ScopeViolation


@dataclass
class Context:
    client: ScopedClient
    policy: Policy
    counter: int = 0
    sessions: dict = field(default_factory=dict)


class Orchestrator:
    def __init__(self, base_url, policy: Policy, source: Path | None = None,
                 memory: ExperienceMemory | None = None, audit_path: Path | None = None, verbose=True,
                 triage=None, use_memory=True, name="target"):
        self.base_url = base_url
        self.policy = policy
        self.source = source
        self.memory = memory if memory is not None else ExperienceMemory()
        self.use_memory = use_memory      # False = "cold" agent (ignores past experience)
        self.triage = triage              # optional trained ML model (ml.triage.TriageModel)
        self.name = name
        self.verbose = verbose
        self.client = ScopedClient(base_url, policy, audit_path)
        self.ctx = Context(self.client, policy)
        self.logs: list[str] = []
        self.plan: list[dict] = []        # kept for the ML dataset collector
        self.first_find_at = None         # position in the exploit queue of the first proof

    def log(self, msg, agent="cart"):
        line = f"[{agent}] {msg}"
        self.logs.append(line)
        if self.verbose:
            print(line)

    def _order_key(self, step):
        """Higher = exploit sooner. Combines ML triage score and experience memory."""
        ml = step.get("ml_score", 0.0) or 0.0
        mem = self.memory.priority(step["module"].vuln_type) if self.use_memory else 0.0
        return (ml, mem)

    def run(self) -> dict:
        t0 = time.time()
        self.log(f"=== scanning {self.base_url} ===")

        recon = ReconAgent(self.client, self.policy, lambda m: self.log(m, "recon")).run()
        modules = [M(self.ctx) for M in ALL_MODULES]
        plan = PlannerAgent(modules, lambda m: self.log(m, "planner")).run(recon)
        self.plan = plan

        # ---- stage 1: DISCOVERY (cheap signals, may be wrong) -----------------
        for step in plan:
            mod, ep, param = step["module"], step["endpoint"], step["param"]
            step["candidate"], step["proven"], step["ml_score"] = None, False, 0.0
            if self.use_memory:
                self.memory.record_attempt(mod.vuln_type)
            try:
                step["candidate"] = mod.discover(ep, param)
            except ScopeViolation as e:
                self.log(f"blocked by policy: {e}", mod.name)
            except Exception as e:
                self.log(f"module error ({mod.name} {ep.path}): {e}", mod.name)
        queue = [s for s in plan if s["candidate"]]
        self.log(f"discovery: {len(queue)} suspicious candidates from {len(plan)} tests", "discover")

        # ---- stage 2: TRIAGE — decide WHICH candidate to exploit first --------
        if self.triage is not None and self.triage.ready:
            for s in queue:
                s["ml_score"] = self.triage.score(vector(extract(s, self.name)))
            self.log("ML triage model scored and ranked the candidates", "triage")
        queue.sort(key=self._order_key, reverse=True)

        # ---- stage 3: PROOF (safe exploitation) -------------------------------
        findings: list[Finding] = []
        proven_keys = set()
        for i, step in enumerate(queue, 1):
            mod = step["module"]
            try:
                finding = mod.exploit(step["candidate"])
            except ScopeViolation as e:
                self.log(f"blocked by policy: {e}", mod.name)
                continue
            except Exception as e:
                self.log(f"exploit error ({mod.name} {step['endpoint'].path}): {e}", mod.name)
                continue
            if not finding:
                continue
            key = (finding.vuln_type, finding.path, finding.param)
            if key in proven_keys:
                step["proven"] = True
                continue
            proven_keys.add(key)
            step["proven"] = True
            findings.append(finding)
            if self.use_memory:
                # key success to the MODULE's attack type so tried/worked stay consistent
                self.memory.record_success(mod.vuln_type, finding.payload)
            if self.first_find_at is None:
                self.first_find_at = i
            self.log(f"PROVEN {finding.id} {finding.vuln_type} @ {finding.path} "
                     f"(sev {finding.severity})", "exploit")

        findings += ChainAgent(self.ctx, lambda m: self.log(m, "chain")).run(findings, recon)
        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -f.cvss))
        RemediationAgent(lambda m: self.log(m, "remediation"), self.source).run(findings)
        self._retest(findings)

        dt = round(time.time() - t0, 1)
        self.log(f"=== done: {len(findings)} proven findings in {dt}s, "
                 f"{self.client.policy.requests_sent} requests ===")
        return {
            "target": self.base_url,
            "recon": {"endpoints": [e.__dict__ for e in recon["endpoints"]],
                      "hidden_paths": recon["hidden_paths"], "server": recon["server"]},
            "findings": [f.to_dict() for f in findings],
            "plan_size": len(plan),
            "candidates": len(queue),
            "requests_sent": self.client.policy.requests_sent,
            "first_find_at": self.first_find_at,
            "used_ml_triage": bool(self.triage is not None and self.triage.ready),
            "used_memory": self.use_memory,
            "duration_s": dt,
            "logs": self.logs,
        }

    # ------------------------------------------------------------------ retest
    def _retest(self, findings):
        """Enable each finding's fix on the live target and re-run the exact proof.

        Needs fix_resolver(finding)->switch and fix_toggle(switch,bool), set by
        the lab runner. Without them (e.g. an external URL) we only note that a
        fix is available.
        """
        resolver = getattr(self, "fix_resolver", None)
        toggle = getattr(self, "fix_toggle", None)
        if not resolver or not toggle:
            for f in findings:
                f.status = "fix_available"
            return
        modmap = {M.vuln_type: M for M in ALL_MODULES}
        for f in findings:
            switch = resolver(f)
            if not switch or f.vuln_type == "privilege_escalation":
                f.status = "fixed_via_root_cause" if f.vuln_type == "privilege_escalation" else "fix_available"
                continue
            toggle(switch, True)
            time.sleep(0.05)
            still = self._reprove(f, modmap)
            toggle(switch, False)
            f.status = "still_vulnerable" if still else "fixed"
            self.log(f"retest {f.id} ({f.vuln_type}@{f.path}): "
                     f"{'STILL VULNERABLE' if still else 'fixed OK'}", "retest")

    def _rebuild_endpoint(self, f):
        from .models import Endpoint
        path = f.path.replace("<id>", "1")
        if f.vuln_type == "sqli_auth_bypass":
            return Endpoint(path, "POST", ["username", "password"]), "username"
        if f.vuln_type in ("info_disclosure", "missing_security_headers"):
            return Endpoint(path, "GET", []), None
        if f.vuln_type == "idor":
            return Endpoint(path, "GET", [], requires_auth=True), None
        param = (f.param or "").split(" ")[0] or None
        return Endpoint(path, f.method, [param] if param else []), param

    def _reprove(self, f, modmap):
        M = modmap.get(f.vuln_type)
        if not M:
            return False
        mod = M(self.ctx)
        ep, param = self._rebuild_endpoint(f)
        try:
            cand = mod.discover(ep, param)
            return bool(cand and mod.exploit(cand))
        except Exception:
            return False

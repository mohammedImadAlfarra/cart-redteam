"""Planner agent: decides WHICH tests to run WHERE.

Rule-based heuristics map every endpoint/parameter that recon discovered to the
attack modules that apply to it, producing the baseline attack plan. The planner
can only choose endpoints and parameters that recon actually found, so the scan
can never be pushed out of scope.
"""
from __future__ import annotations


class PlannerAgent:
    name = "planner"

    def __init__(self, modules, log):
        self.modules = {m.name: m for m in modules}
        self.log = log
        self.reasoning = None

    def run(self, recon):
        eps = recon["endpoints"]
        plan, seen = [], set()

        def add(mod, ep, param, why):
            key = (mod.name, ep.method, ep.path, param)
            if key not in seen:
                seen.add(key)
                plan.append({"module": mod, "endpoint": ep, "param": param, "why": why})

        for ep in eps:
            for mod in self.modules.values():
                for param in mod.targets(ep):
                    add(mod, ep, param, "heuristic")

        self.log(f"attack plan: {len(plan)} tests (rule-based heuristics)")
        return plan

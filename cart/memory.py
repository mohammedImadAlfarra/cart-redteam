"""Experience memory: the agent remembers what worked on earlier targets.

This is a lightweight form of online learning: the agent records a hit-rate per
attack type and, on each new site, tries the attack types that paid off before
FIRST. The benchmark shows the effect as fewer requests-to-first-find on later
targets.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path


class ExperienceMemory:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else None
        self.success = defaultdict(int)       # vuln_type -> times proven
        self.attempts = defaultdict(int)      # vuln_type -> times tried
        self.recipes = {}                     # vuln_type -> last payload that worked
        if self.path and self.path.exists():
            self.load()

    def priority(self, vuln_type: str) -> float:
        a = self.attempts.get(vuln_type, 0)                 # .get: don't create empty keys
        return self.success.get(vuln_type, 0) / a if a else 0.0  # hit-rate; unknown types -> 0

    def record_attempt(self, vuln_type):
        self.attempts[vuln_type] += 1

    def record_success(self, vuln_type, payload=None):
        self.success[vuln_type] += 1
        if payload:
            self.recipes[vuln_type] = payload

    def load(self):
        d = json.loads(self.path.read_text(encoding="utf-8"))
        self.success.update(d.get("success", {}))
        self.attempts.update(d.get("attempts", {}))
        self.recipes.update(d.get("recipes", {}))

    def save(self):
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({
            "success": dict(self.success), "attempts": dict(self.attempts), "recipes": self.recipes,
        }, indent=2), encoding="utf-8")

    def summary(self):
        keys = {k for k in set(self.attempts) | set(self.success)
                if self.attempts.get(k, 0) or self.success.get(k, 0)}
        return {k: {"tried": self.attempts.get(k, 0), "worked": self.success.get(k, 0),
                    "hit_rate": round(self.priority(k), 2)}
                for k in sorted(keys)}

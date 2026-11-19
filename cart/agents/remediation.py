"""Remediation agent: writes a fix for every PROVEN finding.

For each proven finding it looks up the curated knowledge base (CWE/OWASP
mapping, a plain-English fix, and a reference patch) and, when the target's
source file is available, attaches the exact vulnerable code snippet so the
reader can see the root cause next to the recommended fix.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..knowledge import KB


def source_snippet(source: Path | None, path: str, max_lines=30) -> str | None:
    if not source or not source.exists():
        return None
    lines = source.read_text(encoding="utf-8").splitlines()
    prefix = path.split("<")[0].rstrip("/") or "/"
    for i, line in enumerate(lines):
        m = re.search(r'@app\.route\("([^"]+)"', line)
        if m and (m.group(1) == path or (prefix != "/" and m.group(1).startswith(prefix))):
            out = [line]
            for nxt in lines[i + 1:i + max_lines]:
                if nxt.startswith("@app.route") or nxt.startswith("# ---"):
                    break
                out.append(nxt)
            return "\n".join(out).rstrip()
    return None


class RemediationAgent:
    name = "remediation"

    def __init__(self, log, source: Path | None = None):
        self.log, self.source = log, source

    def run(self, findings):
        for f in findings:
            kb = KB[f.vuln_type]
            rem = dict(f.remediation)
            rem.update({"engine": "knowledge-base", "fix": kb["fix"], "reference_patch": kb["patch"]})
            snippet = source_snippet(self.source, f.path)
            if snippet:
                rem["vulnerable_code"] = snippet
            f.remediation = rem
        self.log(f"wrote fixes for {len(findings)} findings")
        return findings

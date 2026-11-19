"""Benchmark runner: scan every lab target, retest fixes, score the agent."""
from __future__ import annotations

import copy
import json
import time
from pathlib import Path

from .memory import ExperienceMemory
from .metrics import aggregate, norm_path, score_target
from .orchestrator import Orchestrator
from .policy import Policy, ScopeViolation
from targets.server import start_targets, stop_targets
from targets.registry import get


def _fix_resolver(ground_truth):
    default = {
        "sqli_auth_bypass": "sqli_login", "sqli": "sqli_search", "xss_reflected": "xss_search",
        "path_traversal": "path_traversal", "idor": "idor", "open_redirect": "open_redirect",
        "info_disclosure": "info_disclosure", "missing_security_headers": "security_headers",
    }
    index = {(g["type"], norm_path(g["path"])): g["fix"] for g in ground_truth}

    def resolve(f):
        return index.get((f.vuln_type, norm_path(f.path))) or default.get(f.vuln_type)
    return resolve


def scan_url(url, policy_path="policy.toml", out_dir="reports",
             verbose=True, auth=None) -> dict:
    """Scan ONE arbitrary URL the user points us at (e.g. a site the professor
    opens on their own laptop). No answer key and no fix toggles, so we prove
    findings and propose fixes, but do not score precision/recall or retest.
    The policy still applies: an out-of-scope host/port is refused.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    policy = Policy.load(policy_path)
    if auth:
        policy.auth = dict(auth)
    memory = ExperienceMemory(out / "experience.json")

    try:
        orch = Orchestrator(url, policy, source=None, memory=memory,
                            audit_path=out / "audit.jsonl", verbose=verbose,
                            triage=None, use_memory=False, name="external")
    except ScopeViolation as e:
        print(f"[policy] REFUSED to scan {url}: {e} -- not allowed by policy.toml. "
              f"Add its host/port to [scope] in policy.toml to authorize it.")
        raise SystemExit(2)
    res = orch.run()
    res["name"], res["title"], res["theme"] = "external", url, "user-provided target"
    res["ground_truth"] = []
    res["score"] = score_target(res["findings"], [], scored=False)
    memory.save()

    report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "engine": "rule-based",
        "external": True,
        "targets": ["external"],
        "results": {"external": res},
        "metrics": aggregate({"external": {"findings": res["findings"], "ground_truth": [], "scored": False}}),
        "experience": {},
        "learning_curve": [],
        "totals": {
            "targets": 1,
            "findings": len(res["findings"]),
            "requests": res["requests_sent"],
            "fixed_on_retest": 0,
        },
    }
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def run_benchmark(names=None, policy_path="policy.toml", out_dir="reports",
                  verbose=True, collector=None, triage=None,
                  use_memory=True, memory_path=None) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    base_policy = Policy.load(policy_path)
    memory = ExperienceMemory(memory_path or (out / "experience.json"))

    targets = get(names)
    running = start_targets([t.name for t in targets], run_dir=out / "_run")
    results, per_target_scores, order = {}, {}, []
    try:
        for t in targets:
            rt = running[t.name]
            policy = copy.deepcopy(base_policy)
            policy.auth = dict(t.auth)  # per-target test account
            try:
                orch = Orchestrator(rt.base_url, policy, source=t.source, memory=memory,
                                    audit_path=out / "audit.jsonl", verbose=verbose,
                                    triage=triage, use_memory=use_memory, name=t.name)
            except ScopeViolation as e:
                print(f"[policy] REFUSED to scan {t.title} ({rt.base_url}): {e} "
                      f"-- not allowed by policy.toml")
                continue
            orch.fix_resolver = _fix_resolver(t.ground_truth)
            orch.fix_toggle = rt.set_fix
            res = orch.run()
            if collector is not None:
                collector.add_scan(orch.plan, t.name)
            rt.reset_fixes()
            res["name"], res["title"], res["theme"] = t.name, t.title, t.theme
            res["ground_truth"] = t.ground_truth
            res["score"] = score_target(res["findings"], t.ground_truth)
            res["memory_priority_at_scan"] = {k: round(memory.priority(k), 2)
                                              for k in {g["type"] for g in t.ground_truth}}
            results[t.name] = res
            per_target_scores[t.name] = {"findings": res["findings"], "ground_truth": t.ground_truth}
            order.append(t.name)
            memory.save()
    finally:
        stop_targets(running)

    metrics = aggregate(per_target_scores)
    report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "engine": "rule-based",
        "targets": order,
        "results": results,
        "metrics": metrics,
        "experience": memory.summary(),
        "learning_curve": [
            {"target": results[n]["title"], "requests": results[n]["requests_sent"],
             "first_find_at": results[n]["first_find_at"], "findings": len(results[n]["findings"])}
            for n in order
        ],
        "totals": {
            "targets": len(order),
            "findings": sum(len(results[n]["findings"]) for n in order),
            "requests": sum(results[n]["requests_sent"] for n in order),
            "fixed_on_retest": sum(1 for n in order for f in results[n]["findings"]
                                   if f["status"] in ("fixed", "fixed_via_root_cause")),
        },
    }
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report

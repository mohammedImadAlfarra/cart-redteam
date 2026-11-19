"""Core tests: policy safety, per-module detection, full benchmark, retest.

These cover ONLY the core pipeline (cart/ + targets/). They do not import the
optional ml/ layer, so the core can be tested even if ml/, dataset/ and models/
have been deleted.

Run:  pytest -q tests/test_core.py
"""
from __future__ import annotations

import pytest

from cart.lab import run_benchmark
from cart.metrics import norm_path, score_target
from cart.policy import Policy, ScopeViolation


# --------------------------------------------------------------- policy / safety
def test_policy_blocks_out_of_scope_host():
    p = Policy.load("policy.toml")
    with pytest.raises(ScopeViolation):
        p.check_url("http://evil.example.com:5000/")


def test_policy_blocks_nonlocal_port_and_method():
    p = Policy.load("policy.toml")
    with pytest.raises(ScopeViolation):
        p.check_method("DELETE")


def test_policy_blocks_destructive_payloads():
    p = Policy.load("policy.toml")
    for bad in ["'; DROP TABLE users; --", "x UNION SELECT load_file('/etc/passwd')", "a; rm -rf /"]:
        with pytest.raises(ScopeViolation):
            p.check_payload(bad)


def test_policy_allows_safe_canary_payload():
    Policy.load("policy.toml").check_payload("<cart-canary-1234>", "../private/canary.txt")


def test_metrics_pathnorm():
    assert norm_path("/api/users/5") == "/api/users/<id>"
    assert norm_path("/Search/") == "/search"


def test_score_counts_false_positive():
    s = score_target([{"vuln_type": "sqli", "path": "/x"}], [])
    assert s["false_positives"] == 1 and s["true_positives"] == 0


# --------------------------------------------------------------- full benchmark
@pytest.fixture(scope="module")
def report():
    return run_benchmark(verbose=False, out_dir="reports")


def test_scanned_all_targets(report):
    assert report["totals"]["targets"] == 6


def test_no_false_positives_on_clean_target(report):
    assert report["results"]["clean"]["score"]["false_positives"] == 0
    assert len(report["results"]["clean"]["findings"]) == 0


def test_overall_precision_perfect(report):
    assert report["metrics"]["overall"]["precision"] == 1.0


def test_overall_recall_high(report):
    assert report["metrics"]["overall"]["recall"] >= 0.9


def test_each_vulnerable_target_detected(report):
    for name in ("bank", "blog", "files", "social", "shop"):
        assert report["results"][name]["score"]["true_positives"] >= 2, name


@pytest.mark.parametrize("vtype", [
    "sqli_auth_bypass", "sqli", "xss_reflected", "path_traversal",
    "idor", "open_redirect", "info_disclosure", "missing_security_headers",
])
def test_vuln_type_detected_somewhere(report, vtype):
    found = {f["vuln_type"] for r in report["results"].values() for f in r["findings"]}
    assert vtype in found


def test_chained_privilege_escalation(report):
    kinds = {f["vuln_type"] for f in report["results"]["shop"]["findings"]}
    assert "privilege_escalation" in kinds


def test_every_finding_has_proof(report):
    for r in report["results"].values():
        for f in r["findings"]:
            assert f["evidence"] and f["proof_request"], f["id"]


def test_all_fixes_verified_on_retest(report):
    for r in report["results"].values():
        for f in r["findings"]:
            assert f["status"] in ("fixed", "fixed_via_root_cause"), (f["id"], f["status"])


def test_request_budget_respected(report):
    assert report["totals"]["requests"] <= 2000

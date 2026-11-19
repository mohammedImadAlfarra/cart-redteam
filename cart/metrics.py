"""Scoring: compare proven findings against ground truth -> precision / recall."""
from __future__ import annotations

import re
from collections import defaultdict


def norm_path(p: str) -> str:
    p = (p or "/").split("?")[0].lower().rstrip("/") or "/"
    p = re.sub(r"<[^>]+>", "<id>", p)
    p = re.sub(r"/\d+", "/<id>", p)
    return p


def _key(vtype, path):
    return (vtype, norm_path(path))


def score_target(findings: list[dict], ground_truth: list[dict], scored: bool = True) -> dict:
    # scored=False: an external URL we were handed at run time has NO answer key,
    # so we report proven findings only, without precision/recall or calling them FPs.
    # (This is different from the clean lab site, whose answer key legitimately says
    #  "zero vulns" -> an unexpected finding there IS a real false positive.)
    if not scored:
        return {
            "expected": 0, "found": len(findings),
            "true_positives": 0, "false_positives": 0, "false_negatives": 0,
            "missed": [], "false_alarms": [], "detection_rate": None, "unscored": True,
        }
    gt = {_key(g["type"], g["path"]): g for g in ground_truth}
    found = {}
    for f in findings:
        found.setdefault(_key(f["vuln_type"], f["path"]), f)
    tp = [gt[k] for k in gt if k in found]
    fn = [gt[k] for k in gt if k not in found]
    fp = [found[k] for k in found if k not in gt]
    return {
        "expected": len(gt), "found": len(found),
        "true_positives": len(tp), "false_positives": len(fp), "false_negatives": len(fn),
        "missed": [g["type"] + " @ " + g["path"] for g in fn],
        "false_alarms": [f["vuln_type"] + " @ " + f["path"] for f in fp],
        "detection_rate": round(len(tp) / len(gt), 3) if gt else None,
    }


def aggregate(per_target: dict[str, dict]) -> dict:
    """per_target: name -> {"findings": [...], "ground_truth": [...]}."""
    by_type = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    rows = {}
    for name, data in per_target.items():
        if data.get("scored") is False:
            rows[name] = score_target(data["findings"], [], scored=False)
            continue  # external target: no answer key -> cannot count TP/FP/FN
        gt = {_key(g["type"], g["path"]): g for g in data["ground_truth"]}
        found = {}
        for f in data["findings"]:
            found.setdefault(_key(f["vuln_type"], f["path"]), f)
        for k, g in gt.items():
            if k in found:
                by_type[g["type"]]["tp"] += 1
            else:
                by_type[g["type"]]["fn"] += 1
        for k, f in found.items():
            if k not in gt:
                by_type[f["vuln_type"]]["fp"] += 1
        rows[name] = score_target(data["findings"], data["ground_truth"])

    per_type = {}
    T = {"tp": 0, "fp": 0, "fn": 0}
    for vtype, c in sorted(by_type.items()):
        for k in T:
            T[k] += c[k]
        per_type[vtype] = _pr(c)
    return {"per_target": rows, "per_type": per_type, "overall": _pr(T)}


def _pr(c):
    tp, fp, fn = c["tp"], c["fp"], c["fn"]
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision and recall and (precision + recall) else None)
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 3) if precision is not None else None,
            "recall": round(recall, 3) if recall is not None else None,
            "f1": round(f1, 3) if f1 is not None else None}

"""Feature extraction for the machine-learning dataset.

Every planned test (module x endpoint x parameter) becomes ONE row:
  * features  - cheap facts the agent already knows BEFORE the exploit step
                (parameter name, path hints, method, discovery signal, ...)
  * label     - 1 if the safe exploit later PROVED a real vulnerability, else 0

No extra HTTP requests are made: we only describe what recon and discovery
already observed. The trained model can then predict which candidates are
worth exploiting first (triage).
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

ID_NAMES = {"id", "uid", "pid", "user_id", "account", "accountid"}
FILE_NAMES = {"file", "path", "page", "doc", "template", "dir", "f", "filename", "download"}
REDIRECT_NAMES = {"next", "url", "redirect", "return", "returnto", "goto", "dest", "target", "continue"}
SEARCH_NAMES = {"q", "query", "search", "s", "term", "holder", "text", "name", "keyword"}
DEBUG_HINTS = ("debug", "config", "env", "status", "info", "phpinfo", "backup")
MODULES = ("sqli", "xss", "traversal", "redirect", "idor", "infoleak", "headers")

FEATURES = [
    # module being tried (one-hot)
    *[f"mod_{m}" for m in MODULES],
    # endpoint facts
    "method_post", "requires_auth", "src_form", "src_robots", "status_2xx", "status_4xx",
    "path_root", "path_api", "path_numeric", "path_debug", "path_admin",
    # parameter facts
    "has_param", "p_id", "p_file", "p_redirect", "p_search", "p_pass", "p_user",
    # discovery stage outcome
    "flagged", "sig_error", "sig_reflect", "sig_name", "sig_passive",
]
META = ["target", "module", "method", "path", "param", "signal"]
LABEL = "proven"


def _sig_kind(signal: str) -> str:
    s = (signal or "").lower()
    if "sql error" in s or "http 5" in s:
        return "error"
    if "reflected" in s:
        return "reflect"
    if "passive" in s:
        return "passive"
    return "name" if s else ""


def extract(step: dict, target: str) -> dict:
    mod, ep, param = step["module"], step["endpoint"], step.get("param")
    cand = step.get("candidate")
    pname = (param or "").lower()
    path = (ep.path or "/").lower()
    sig = cand.signal if cand else ""
    kind = _sig_kind(sig)
    status = ep.status or 0
    row = {f"mod_{m}": int(mod.name == m) for m in MODULES}
    row.update({
        "method_post": int(ep.method == "POST"),
        "requires_auth": int(bool(ep.requires_auth)),
        "src_form": int(ep.source == "form"),
        "src_robots": int(ep.source == "robots"),
        "status_2xx": int(200 <= status < 300),
        "status_4xx": int(400 <= status < 500),
        "path_root": int(path == "/"),
        "path_api": int("/api/" in path),
        "path_numeric": int(bool(re.search(r"/\d+(/|$)", path))),
        "path_debug": int(any(h in path for h in DEBUG_HINTS)),
        "path_admin": int("admin" in path),
        "has_param": int(bool(param)),
        "p_id": int(pname in ID_NAMES or pname.endswith("_id")),
        "p_file": int(pname in FILE_NAMES),
        "p_redirect": int(pname in REDIRECT_NAMES),
        "p_search": int(pname in SEARCH_NAMES),
        "p_pass": int("pass" in pname),
        "p_user": int("user" in pname),
        "flagged": int(cand is not None),
        "sig_error": int(kind == "error"),
        "sig_reflect": int(kind == "reflect"),
        "sig_name": int(kind == "name"),
        "sig_passive": int(kind == "passive"),
    })
    row.update({"target": target, "module": mod.name, "method": ep.method, "path": ep.path,
                "param": param or "", "signal": sig, LABEL: int(bool(step.get("proven")))})
    return row


class FeatureCollector:
    """Collects one row per planned test across one or more scans."""

    def __init__(self):
        self.rows: list[dict] = []

    def add_scan(self, plan: list[dict], target: str):
        self.rows.extend(extract(step, target) for step in plan)

    def save(self, path: Path, targets: list[str] | None = None) -> int:
        rows = [r for r in self.rows if targets is None or r["target"] in targets]
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=META + FEATURES + [LABEL])
            w.writeheader()
            for r in rows:
                w.writerow({k: r[k] for k in META + FEATURES + [LABEL]})
        return len(rows)


def vector(row: dict) -> list[int]:
    return [int(row[f]) for f in FEATURES]

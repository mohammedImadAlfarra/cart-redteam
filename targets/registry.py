"""The lab catalogue: every target, its port, login, source file and GROUND TRUTH.

Ground truth is the real answer key. The scanner never reads it; the benchmark
uses it to score precision / recall per vulnerability type.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from . import sites

BASE = Path(__file__).resolve().parent
SITES_SRC = BASE / "sites.py"
SHOP_SRC = BASE / "vuln_app" / "app.py"
FILES_STATE = BASE / "_state_files"   # where the CloudFiles canary lives


@dataclass
class Target:
    name: str
    title: str
    port: int
    theme: str                       # the vuln class this site is "about"
    ground_truth: list[dict]
    build: callable                  # (fixes_path) -> Flask app
    source: Path
    auth: dict = field(default_factory=dict)
    decoys: list[str] = field(default_factory=list)

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.port}"


def _shop(fixes_path):
    os.environ["VULNSHOP_FIXES"] = str(fixes_path)
    from .vuln_app import app as shop_mod
    shop_mod.FIXES_FILE = Path(fixes_path)   # re-point on every start (module is imported once)
    return shop_mod.app


HEADERS_GT = {"type": "missing_security_headers", "path": "/", "fix": "security_headers"}

TARGETS: list[Target] = [
    Target(
        name="bank", title="MicroBank", port=5001, theme="SQL injection",
        ground_truth=[
            {"id": "BANK-1", "type": "sqli_auth_bypass", "path": "/login", "fix": "sqli_login"},
            {"id": "BANK-2", "type": "sqli", "path": "/accounts", "fix": "sqli_search"},
            {"id": "BANK-3", **HEADERS_GT},
        ],
        build=sites.make_bank, source=SITES_SRC, auth={"username": "sara", "password": "sara2024"},
    ),
    Target(
        name="blog", title="DevBlog", port=5002, theme="Cross-site scripting (XSS)",
        ground_truth=[
            {"id": "BLOG-1", "type": "xss_reflected", "path": "/search", "fix": "xss_search"},
            {"id": "BLOG-2", "type": "xss_reflected", "path": "/comment", "fix": "xss_comment"},
            {"id": "BLOG-3", **HEADERS_GT},
        ],
        build=sites.make_blog, source=SITES_SRC, decoys=["/hello"],
    ),
    Target(
        name="files", title="CloudFiles", port=5003, theme="Path traversal & info disclosure",
        ground_truth=[
            {"id": "FILE-1", "type": "path_traversal", "path": "/download", "fix": "path_traversal"},
            {"id": "FILE-2", "type": "info_disclosure", "path": "/debug", "fix": "info_disclosure"},
            {"id": "FILE-3", **HEADERS_GT},
        ],
        build=lambda fp: sites.make_files(fp, FILES_STATE), source=SITES_SRC, decoys=["/view"],
    ),
    Target(
        name="social", title="Chatly", port=5004, theme="Access control (IDOR) & open redirect",
        ground_truth=[
            {"id": "SOC-1", "type": "idor", "path": "/api/profile/<id>", "fix": "idor"},
            {"id": "SOC-2", "type": "open_redirect", "path": "/go", "fix": "open_redirect"},
            {"id": "SOC-3", **HEADERS_GT},
        ],
        build=sites.make_social, source=SITES_SRC, auth={"username": "lina", "password": "lina123"},
    ),
    Target(
        name="shop", title="VulnShop", port=5000, theme="Everything + chained privilege escalation",
        ground_truth=[
            {"id": "SHOP-1", "type": "sqli_auth_bypass", "path": "/login", "fix": "sqli_login"},
            {"id": "SHOP-2", "type": "sqli", "path": "/search", "fix": "sqli_search"},
            {"id": "SHOP-3", "type": "xss_reflected", "path": "/search", "fix": "xss_search"},
            {"id": "SHOP-4", "type": "path_traversal", "path": "/download", "fix": "path_traversal"},
            {"id": "SHOP-5", "type": "idor", "path": "/api/users/<id>", "fix": "idor"},
            {"id": "SHOP-6", "type": "open_redirect", "path": "/redirect", "fix": "open_redirect"},
            {"id": "SHOP-7", "type": "info_disclosure", "path": "/debug", "fix": "info_disclosure"},
            {"id": "SHOP-8", **HEADERS_GT},
            {"id": "SHOP-9", "type": "privilege_escalation", "path": "/admin", "fix": "sqli_login"},
        ],
        build=_shop, source=SHOP_SRC, auth={"username": "alice", "password": "alice123"},
        decoys=["/greet", "/docs", "/products"],
    ),
    Target(
        name="clean", title="SecureCorp", port=5005, theme="No vulnerabilities (false-positive control)",
        ground_truth=[],
        build=sites.make_clean, source=SITES_SRC, decoys=["/search", "/profile"],
    ),
]

BY_NAME = {t.name: t for t in TARGETS}


def get(names=None) -> list[Target]:
    if not names:
        return TARGETS
    return [BY_NAME[n] for n in names if n in BY_NAME]

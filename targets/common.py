"""Shared helpers for the small vulnerable lab targets.

Every target is an INTENTIONALLY VULNERABLE Flask app used only as a practice
target for CART. Each app:
  * binds to 127.0.0.1 only,
  * reads a per-app fixes.json so a vulnerability can be "patched" at runtime
    (this is what lets CART demonstrate find -> prove -> FIX -> retest),
  * ships a ground-truth list so the benchmark can score the agent.
"""
from __future__ import annotations

import json
import secrets
from pathlib import Path


def fixes_reader(fixes_path: Path):
    def fixed(name: str) -> bool:
        try:
            return bool(json.loads(Path(fixes_path).read_text(encoding="utf-8")).get(name, False))
        except Exception:
            return False
    return fixed


def shell(body: str, title: str, nav: list[tuple[str, str]]) -> str:
    links = " | ".join(f"<a href='{href}'>{text}</a>" for text, href in nav)
    return (
        f"<html><head><title>{title}</title></head><body>"
        f"<h1>{title}</h1><nav><a href='/'>Home</a> | {links}</nav><hr>{body}</body></html>"
    )


def plant_canary(private_dir: Path) -> str:
    private_dir.mkdir(parents=True, exist_ok=True)
    token = "CART-CANARY-" + secrets.token_hex(8)
    (private_dir / "canary.txt").write_text(token + "\n", encoding="utf-8")
    return token

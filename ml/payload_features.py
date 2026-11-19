"""Turn an HTTP parameter payload into interpretable numeric features.

These features are deliberately simple and human-readable so the trained model
and its feature-importance chart are easy to explain in the report: malicious
payloads tend to be longer and richer in special characters, SQL keywords,
script markers, traversal sequences and command-injection metacharacters.
"""
from __future__ import annotations

import math
import re

SQL_KW = re.compile(r"\b(select|union|insert|update|delete|drop|or|and|where|from|"
                    r"exec|concat|char|sleep|benchmark|information_schema)\b", re.I)
XSS_KW = re.compile(r"(<script|</script|onerror|onload|alert\(|javascript:|<img|<svg|%3cscript)", re.I)
CMD_KW = re.compile(r"(;|\|\||&&|`|\$\(|\bcat\b|\bwhoami\b|\bping\b|/bin/|cmd\.exe)", re.I)
TRAVERSAL = re.compile(r"(\.\./|\.\.\\|%2e%2e|/etc/passwd|\.\.%2f|boot\.ini)", re.I)
SPECIALS = "'\"<>();=/\\%&|-*#"

FEATURES = [
    "length", "n_digits", "n_letters", "n_specials", "special_ratio", "n_spaces",
    "n_single_quote", "n_double_quote", "n_angle", "n_equals", "n_percent",
    "n_semicolon", "sql_kw", "xss_kw", "cmd_kw", "traversal", "entropy", "non_ascii",
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return round(-sum((v / n) * math.log2(v / n) for v in counts.values()), 3)


def featurize(payload: str) -> dict:
    p = payload or ""
    low = p.lower()
    length = len(p)
    specials = sum(p.count(c) for c in SPECIALS)
    return {
        "length": length,
        "n_digits": sum(c.isdigit() for c in p),
        "n_letters": sum(c.isalpha() for c in p),
        "n_specials": specials,
        "special_ratio": round(specials / length, 3) if length else 0.0,
        "n_spaces": p.count(" "),
        "n_single_quote": p.count("'"),
        "n_double_quote": p.count('"'),
        "n_angle": p.count("<") + p.count(">"),
        "n_equals": p.count("="),
        "n_percent": p.count("%"),
        "n_semicolon": p.count(";"),
        "sql_kw": len(SQL_KW.findall(low)),
        "xss_kw": len(XSS_KW.findall(low)),
        "cmd_kw": len(CMD_KW.findall(low)),
        "traversal": len(TRAVERSAL.findall(low)),
        "entropy": _entropy(p),
        "non_ascii": sum(ord(c) > 127 for c in p),
    }


def vector(payload: str) -> list[float]:
    f = featurize(payload)
    return [f[k] for k in FEATURES]

"""Load the real HTTP Params dataset and build the processed feature table.

  dataset/raw/http_params_dataset.csv   (downloaded real dataset, MIT licence)
        |  payload_features.featurize
        v
  dataset/processed/features.csv        (numeric features + binary label)

If the raw file is missing, we try to download it; if the network is blocked,
we fall back to a tiny bundled sample so the pipeline still runs, and say so.
"""
from __future__ import annotations

import csv
from pathlib import Path

from .payload_features import FEATURES, featurize

RAW = Path("dataset/raw/http_params_dataset.csv")
PROCESSED = Path("dataset/processed/features.csv")
RAW_URL = "https://raw.githubusercontent.com/Morzeux/HttpParamsDataset/master/payload_full.csv"

# minimal offline fallback so the demo never hard-fails (clearly marked)
_SAMPLE = [
    ("c/ caridad s/n", "norm"), ("campello el", "norm"), ("john.doe@mail.com", "norm"),
    ("12 de octubre", "norm"), ("barcelona 08001", "norm"), ("usuario123", "norm"),
    ("' or '1'='1", "anom"), ("1 UNION SELECT username,password FROM users", "anom"),
    ("<script>alert(1)</script>", "anom"), ("../../etc/passwd", "anom"),
    ("; cat /etc/passwd", "anom"), ("admin'--", "anom"),
]


def ensure_raw() -> tuple[Path, bool]:
    """Returns (path, is_real). is_real=False means the bundled sample is used."""
    if RAW.exists() and RAW.stat().st_size > 10_000:
        return RAW, True
    RAW.parent.mkdir(parents=True, exist_ok=True)
    try:
        import urllib.request
        urllib.request.urlretrieve(RAW_URL, RAW)
        if RAW.stat().st_size > 10_000:
            return RAW, True
    except Exception:
        pass
    # fallback sample
    with open(RAW, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["payload", "length", "attack_type", "label"])
        for pay, lab in _SAMPLE:
            w.writerow([pay, len(pay), lab if lab == "norm" else "sqli", lab])
    return RAW, False


def load_raw():
    path, is_real = ensure_raw()
    with open(path, encoding="utf-8", errors="replace") as f:
        rows = list(csv.DictReader(f))
    return rows, is_real


def build_processed() -> tuple[Path, bool, int]:
    rows, is_real = load_raw()
    PROCESSED.parent.mkdir(parents=True, exist_ok=True)
    with open(PROCESSED, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["attack_type", *FEATURES, "label"])
        w.writeheader()
        for r in rows:
            feats = featurize(r["payload"])
            w.writerow({"attack_type": r.get("attack_type", ""),
                        **feats, "label": 1 if r["label"] == "anom" else 0})
    return PROCESSED, is_real, len(rows)


def load_processed():
    if not PROCESSED.exists():
        build_processed()
    with open(PROCESSED, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    X = [[float(r[c]) for c in FEATURES] for r in rows]
    y = [int(r["label"]) for r in rows]
    return X, y, rows


if __name__ == "__main__":
    p, real, n = build_processed()
    print(f"processed {n} rows -> {p}  ({'REAL dataset' if real else 'bundled sample fallback'})")

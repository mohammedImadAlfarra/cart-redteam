"""Tests for the OPTIONAL ml/ layer.

These are skipped automatically if scikit-learn or the ml/ package is absent,
so deleting the ML layer does not make the (core) test run fail.

Run:  pytest -q tests/test_ml.py
"""
from __future__ import annotations

import pytest

pytest.importorskip("sklearn")
ml_dataset = pytest.importorskip("ml.dataset")
from ml.payload_features import FEATURES, featurize, vector  # noqa: E402


def test_featurize_flags_sql_injection():
    f = featurize("' OR 1=1 --")
    assert f["sql_kw"] >= 1 and f["n_single_quote"] >= 1


def test_featurize_flags_xss():
    assert featurize("<script>alert(1)</script>")["xss_kw"] >= 1


def test_featurize_flags_traversal():
    assert featurize("../../etc/passwd")["traversal"] >= 1


def test_benign_payload_is_calm():
    f = featurize("barcelona 08001")
    assert f["sql_kw"] == 0 and f["xss_kw"] == 0 and f["traversal"] == 0


def test_vector_matches_feature_count():
    assert len(vector("test")) == len(FEATURES)


@pytest.mark.slow
def test_train_reaches_high_accuracy(tmp_path):
    # trains on the real dataset (downloads once, or uses bundled sample offline)
    from ml.train import train
    m = train()
    assert m["accuracy"] >= 0.9
    assert set(m["confusion_matrix"]) == {"tn", "fp", "fn", "tp"}

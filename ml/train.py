"""Train the malicious-request classifier on the REAL HTTP Params dataset.

  * RandomForest on interpretable payload features
  * stratified train/test split  -> headline accuracy / precision / recall / F1
  * 5-fold stratified CROSS-VALIDATION -> mean +/- std (guards against a lucky split)
  * LEAVE-ONE-ATTACK-TYPE-OUT generalization -> can the model flag an attack
    family it never saw during training? (honest out-of-distribution test)
  * confusion matrix, feature-importance, learning-curve and generalization charts
  * saves model + metrics.json + the four charts under models/request_classifier/

Run:  python -m ml.train     (or  python run.py --ml-only)
Optional layer: nothing in cart/ imports it.
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split

from ml.dataset import build_processed, load_processed
from ml.payload_features import FEATURES

OUT = Path("models/request_classifier")
# attack families to hold out, one at a time, for the generalization test
HELD_OUT_TYPES = ["sqli", "xss", "cmdi", "path-traversal"]


def _rf(seed=42):
    return RandomForestClassifier(n_estimators=200, max_depth=16, random_state=seed, n_jobs=-1)


def _plot_confusion(cm, path):
    fig, ax = plt.subplots(figsize=(4.2, 4))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1], ["normal", "malicious"])
    ax.set_yticks([0, 1], ["normal", "malicious"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
    ax.set_title("Confusion matrix (test set)")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{int(cm[i, j]):,}", ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "#0f172a", fontsize=13, fontweight="bold")
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


def _plot_importance(clf, path):
    imp = clf.feature_importances_
    idx = np.argsort(imp)[-12:]
    fig, ax = plt.subplots(figsize=(7, 4.6))
    ax.barh([FEATURES[i] for i in idx], imp[idx], color="#2563eb")
    ax.set_title("Top payload features for detecting attacks"); ax.set_xlabel("importance")
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


def _plot_learning_curve(X_tr, y_tr, X_te, y_te, seed, path):
    fracs = [0.1, 0.25, 0.5, 0.75, 1.0]
    accs = []
    n = len(X_tr)
    for fr in fracs:
        k = max(10, int(n * fr))
        clf = RandomForestClassifier(n_estimators=120, max_depth=14, random_state=seed, n_jobs=-1)
        clf.fit(X_tr[:k], y_tr[:k])
        accs.append(accuracy_score(y_te, clf.predict(X_te)))
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot([int(n * f) for f in fracs], accs, marker="o", color="#16a34a")
    ax.set_xlabel("training examples"); ax.set_ylabel("test accuracy")
    ax.set_title("Learning curve: accuracy improves with more data")
    ax.grid(alpha=.3)
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)
    return [{"train_size": int(n * f), "accuracy": round(float(a), 4)} for f, a in zip(fracs, accs)]


def _plot_generalization(gen, path):
    """Bar chart: recall on each attack family the model NEVER trained on."""
    types = [g["attack_type"] for g in gen]
    recalls = [g["recall"] for g in gen]
    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar(types, recalls, color="#ea580c")
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("recall on unseen family")
    ax.set_title("Generalization: catch rate on an attack type held out of training")
    for b, r in zip(bars, recalls):
        ax.text(b.get_x() + b.get_width() / 2, r + 0.02, f"{r:.2f}", ha="center", fontsize=10)
    ax.grid(alpha=.3, axis="y")
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


def _cross_validate(X, y, seed=42) -> dict:
    """5-fold stratified CV on the full dataset: mean +/- std for each metric.

    If CV mean is close to the single-split test score with a small std, the
    headline numbers are not the result of one lucky train/test split.
    """
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    scoring = ["accuracy", "precision", "recall", "f1"]
    cv = cross_validate(_rf(seed), X, y, cv=skf, scoring=scoring, n_jobs=-1)
    return {m: {"mean": round(float(cv[f"test_{m}"].mean()), 4),
                "std": round(float(cv[f"test_{m}"].std()), 4)}
            for m in scoring}


def _generalization(X, y, attack_types, seed=42) -> list[dict]:
    """Leave-one-attack-type-out: train WITHOUT one attack family, then measure
    how many of that unseen family's malicious samples the model still catches."""
    at = np.asarray(attack_types)
    results = []
    for t in HELD_OUT_TYPES:
        test_mask = at == t
        n_held = int(test_mask.sum())
        if n_held == 0:
            continue
        train_mask = ~test_mask                      # all benign + every OTHER attack family
        clf = _rf(seed)
        clf.fit(X[train_mask], y[train_mask])
        pred = clf.predict(X[test_mask])
        caught = int(pred.sum())                     # held-out rows are all malicious (label 1)
        results.append({
            "attack_type": t,
            "held_out_malicious": n_held,
            "caught": caught,
            "recall": round(caught / n_held, 4),
        })
    return results


def train(seed=42) -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    _, is_real, n_raw = build_processed()
    X, y, rows = load_processed()
    X, y = np.array(X), np.array(y)
    attack_types = [r.get("attack_type", "") for r in rows]
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.3, random_state=seed, stratify=y)

    clf = _rf(seed)
    clf.fit(X_tr, y_tr)
    pred = clf.predict(X_te)
    cm = confusion_matrix(y_te, pred, labels=[0, 1])

    metrics = {
        "dataset": "HTTP Params Dataset (Morzeux) - benign values from CSIC 2010; MIT licence",
        "dataset_url": "https://github.com/Morzeux/HttpParamsDataset",
        "is_real_dataset": bool(is_real),
        "total_rows": int(n_raw),
        "model": "RandomForestClassifier(n_estimators=200, max_depth=16)",
        "features": FEATURES,
        "train_size": int(len(X_tr)), "test_size": int(len(X_te)),
        "accuracy": round(float(accuracy_score(y_te, pred)), 4),
        "precision": round(float(precision_score(y_te, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_te, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_te, pred, zero_division=0)), 4),
        "confusion_matrix": {"tn": int(cm[0, 0]), "fp": int(cm[0, 1]),
                             "fn": int(cm[1, 0]), "tp": int(cm[1, 1])},
    }
    metrics["learning_curve"] = _plot_learning_curve(X_tr, y_tr, X_te, y_te, seed,
                                                     OUT / "learning_curve.png")
    metrics["cross_validation"] = _cross_validate(X, y, seed)
    metrics["generalization"] = _generalization(X, y, attack_types, seed)
    if metrics["generalization"]:
        _plot_generalization(metrics["generalization"], OUT / "generalization.png")

    import joblib
    joblib.dump({"clf": clf, "features": FEATURES}, OUT / "model.joblib")
    (OUT / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    _plot_confusion(cm, OUT / "confusion_matrix.png")
    _plot_importance(clf, OUT / "feature_importance.png")
    return metrics


def main():
    m = train()
    print("=" * 60)
    print("  Malicious HTTP-request classifier (real dataset)")
    print("=" * 60)
    print(f"  Dataset   : {m['dataset']}")
    print(f"  Rows      : {m['total_rows']:,}  ({'REAL' if m['is_real_dataset'] else 'SAMPLE fallback'})")
    print(f"  Train/test: {m['train_size']:,} / {m['test_size']:,}")
    print(f"  Accuracy  : {m['accuracy']}")
    print(f"  Precision : {m['precision']}   Recall: {m['recall']}   F1: {m['f1']}")
    c = m["confusion_matrix"]
    print(f"  Confusion : TP={c['tp']:,} TN={c['tn']:,} FP={c['fp']:,} FN={c['fn']:,}")
    cv = m.get("cross_validation", {})
    if cv:
        print("-" * 60)
        print("  5-fold cross-validation (mean +/- std):")
        for k, v in cv.items():
            print(f"    {k:10}: {v['mean']} +/- {v['std']}")
    gen = m.get("generalization", [])
    if gen:
        print("-" * 60)
        print("  Leave-one-attack-type-out (recall on an UNSEEN attack family):")
        for g in gen:
            print(f"    {g['attack_type']:16}: {g['caught']}/{g['held_out_malicious']} "
                  f"caught  (recall {g['recall']})")
    print("=" * 60)
    print(f"  Saved -> {OUT}/ (model.joblib, metrics.json, 4 charts)")
    print("=" * 60)


if __name__ == "__main__":
    main()

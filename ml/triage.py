"""TriageModel: a thin wrapper around the trained scikit-learn classifier.

The core pipeline (cart/) imports this ONLY when the lab runner is given a
model, and the runner loads it lazily. If scikit-learn or the model file is
missing, `TriageModel.load` returns a model with `.ready == False`, and the
orchestrator silently falls back to experience-memory ordering.
"""
from __future__ import annotations

from pathlib import Path

DEFAULT_PATH = Path("models/vuln_classifier/model.joblib")


class TriageModel:
    def __init__(self, clf=None, features=None):
        self.clf = clf
        self.features = features
        self.ready = clf is not None

    def score(self, vec) -> float:
        """Probability this candidate is a real vulnerability (0..1)."""
        if not self.ready:
            return 0.0
        try:
            return float(self.clf.predict_proba([vec])[0][1])
        except Exception:
            return 0.0

    @classmethod
    def load(cls, path=DEFAULT_PATH) -> "TriageModel":
        try:
            import joblib
            bundle = joblib.load(path)
            return cls(bundle["clf"], bundle["features"])
        except Exception:
            return cls(None)

    def save(self, path=DEFAULT_PATH):
        import joblib
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"clf": self.clf, "features": self.features}, path)

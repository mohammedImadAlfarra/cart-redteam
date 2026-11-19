"""Two things, both honest and reproducible:

1. EXPERIENCE MEMORY (the agent's own learning): after scanning the lab, the
   agent holds a per-attack-type success table and orders future attempts by it.
   We export that table — it is a real artifact, not a claimed speed-up.

2. CROSS-CHECK: load the trained malicious-request classifier (real dataset)
   and run it over the payloads the agent ACTUALLY sent during the scan
   (reports/audit.jsonl). A high "flagged malicious" rate shows the independent,
   recognised-dataset model agrees the agent's attacks look malicious — a
   concrete link between the supervised model and the live agent.

Saves models/experience_memory/{experience.json, learning_demo.json}.
Optional layer: nothing in cart/ imports it.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from cart.lab import run_benchmark
from cart.memory import ExperienceMemory

OUT = Path("models/experience_memory")


def _agent_payloads(audit_path: Path) -> list[str]:
    vals = []
    if not audit_path.exists():
        return vals
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        try:
            e = json.loads(line)
        except Exception:
            continue
        for v in (e.get("data") or {}).values():
            vals.append(str(v))
        for v in parse_qs(urlsplit(e.get("url", "")).query).values():
            vals.extend(v)
    return [v for v in vals if v and v != "test"]


def run(out_dir="reports") -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    audit = Path(out_dir) / "audit.jsonl"
    audit.unlink(missing_ok=True)
    (OUT / "experience.json").unlink(missing_ok=True)  # start each demo from a clean slate

    mem = ExperienceMemory(OUT / "experience.json")
    run_benchmark(verbose=False, memory_path=OUT / "experience.json", out_dir=out_dir)
    mem = ExperienceMemory(OUT / "experience.json")

    demo = {
        "experience_memory": {
            "what": "The agent records, per attack type, how often an exploit attempt was proven, and "
                    "tries higher hit-rate attacks first on later targets.",
            "table": mem.summary(),
        }
    }

    # cross-check with the real-dataset classifier, if it has been trained
    try:
        import joblib
        from ml.payload_features import vector
        bundle = joblib.load("models/request_classifier/model.joblib")
        clf = bundle["clf"]
        payloads = _agent_payloads(audit)
        if payloads:
            preds = clf.predict([vector(p) for p in payloads])
            flagged = int(sum(preds))
            demo["agent_payload_crosscheck"] = {
                "what": "Fraction of the agent's own request values that the real-dataset classifier "
                        "independently labels as malicious.",
                "agent_values_checked": len(payloads),
                "flagged_malicious": flagged,
                "flagged_rate": round(flagged / len(payloads), 3),
            }
    except Exception as e:
        demo["agent_payload_crosscheck"] = {"skipped": f"classifier not available ({e})"}

    (OUT / "learning_demo.json").write_text(json.dumps(demo, indent=2), encoding="utf-8")
    return demo


def main():
    demo = run()
    print("=" * 60)
    print("  Experience memory (agent hit-rate table)")
    print("=" * 60)
    for t, d in demo["experience_memory"]["table"].items():
        print(f"  {t:22} tried={d['tried']:2} worked={d['worked']:2} hit_rate={d['hit_rate']}")
    cc = demo.get("agent_payload_crosscheck", {})
    if "flagged_rate" in cc:
        print("-" * 60)
        print(f"  Classifier cross-check: {cc['flagged_malicious']}/{cc['agent_values_checked']} "
              f"of the agent's attack values flagged malicious ({cc['flagged_rate']*100:.0f}%)")
    print("=" * 60)


if __name__ == "__main__":
    main()

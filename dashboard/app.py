"""Simple Streamlit dashboard for CART results.

Run:  streamlit run dashboard/app.py
It reads reports/report.json (run `python run.py` first).
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / "reports" / "report.json"

st.set_page_config(page_title="CART Dashboard", layout="wide")
st.title("🛡️ CART — Continuous Automated Red Teaming")

if not REPORT.exists():
    st.warning("No report found. Run `python run.py` first to generate reports/report.json.")
    st.stop()

report = json.loads(REPORT.read_text(encoding="utf-8"))
m = report["metrics"]["overall"]
t = report["totals"]

st.caption(f"Generated {report['generated_at']}")

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Proven findings", t["findings"])
c2.metric("Precision", m["precision"])
c3.metric("Recall", m["recall"])
c4.metric("F1 score", m["f1"])
c5.metric("Fixed on retest", f"{t['fixed_on_retest']}/{t['findings']}")

st.subheader("Detection accuracy by vulnerability type")
pt = pd.DataFrame(report["metrics"]["per_type"]).T
st.dataframe(pt, use_container_width=True)
st.bar_chart(pt[["precision", "recall"]])

st.subheader("Findings per target")
rows = [{"target": report["results"][n]["title"],
         "theme": report["results"][n]["theme"],
         "findings": len(report["results"][n]["findings"]),
         "requests": report["results"][n]["requests_sent"],
         "detected": report["results"][n]["score"]["true_positives"],
         "expected": report["results"][n]["score"]["expected"],
         "false_positives": report["results"][n]["score"]["false_positives"]}
        for n in report["targets"]]
st.dataframe(pd.DataFrame(rows), use_container_width=True)

st.subheader("Agent experience memory")
st.caption("Attack types the agent learned work, and tries first on later targets.")
st.dataframe(pd.DataFrame(report["experience"]).T, use_container_width=True)

# ---- optional ML layer (shown only if it has been trained) ------------------
clf_metrics = ROOT / "models" / "request_classifier" / "metrics.json"
if clf_metrics.exists():
    st.subheader("Machine-learning layer (real dataset)")
    mlm = json.loads(clf_metrics.read_text(encoding="utf-8"))
    st.caption(f"{mlm.get('dataset','')} · {mlm.get('total_rows',0):,} rows · "
               f"[source]({mlm.get('dataset_url','')})")
    a, b, c, d = st.columns(4)
    a.metric("Accuracy", mlm.get("accuracy"))
    b.metric("Precision", mlm.get("precision"))
    c.metric("Recall", mlm.get("recall"))
    d.metric("F1", mlm.get("f1"))
    cols = st.columns(3)
    for col, img in zip(cols, ["confusion_matrix.png", "learning_curve.png", "feature_importance.png"]):
        p = ROOT / "models" / "request_classifier" / img
        if p.exists():
            col.image(str(p))
    demo = ROOT / "models" / "experience_memory" / "learning_demo.json"
    if demo.exists():
        d2 = json.loads(demo.read_text(encoding="utf-8"))
        tbl = d2.get("experience_memory", {}).get("table")
        if tbl:
            st.caption("Agent experience memory — per-attack hit rate")
            st.dataframe(pd.DataFrame(tbl).T, use_container_width=True)
        cc = d2.get("agent_payload_crosscheck", {})
        if "flagged_rate" in cc:
            st.info(f"Independent classifier flags {cc['flagged_malicious']}/{cc['agent_values_checked']} "
                    f"({int(cc['flagged_rate']*100)}%) of the agent's attack values as malicious.")

st.subheader("Explore a target")
choice = st.selectbox("Target", report["targets"],
                      format_func=lambda n: report["results"][n]["title"])
res = report["results"][choice]
graph = ROOT / "reports" / "graphs" / f"{choice}.png"
if graph.exists():
    st.image(str(graph), caption=f"Attack-path graph — {res['title']}")

for f in res["findings"]:
    with st.expander(f"{f['id']} · {f['title']} — {f['severity'].upper()} (CVSS {f['cvss']}) — {f['status']}"):
        st.write(f"**{f['method']} `{f['path']}`** · {f['cwe']} · {f['owasp']}")
        if f.get("payload"):
            st.code(f["payload"], language="text")
        st.info(f"**Proof:** {f['evidence']}")
        st.write(f"**Impact:** {f['impact']}")
        rem = f.get("remediation", {})
        st.write(f"**Fix ({rem.get('engine','knowledge-base')}):** "
                 f"{rem.get('fix','')}")
        patch = rem.get("reference_patch")
        if patch:
            st.code(patch, language="python")

if not res["findings"]:
    st.success("No findings — this is the clean control target (no false positives). ✅")

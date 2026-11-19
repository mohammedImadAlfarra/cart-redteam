"""Render the benchmark report: an interactive HTML page (+ console summary).

The page has two top-level tabs:
  * CART  — the security scan. Summary cards + overview tables are always shown;
            a target picker lets the reader open ONE site at a time and filter
            its findings by attack type. Every finding is laid out as a staged
            table (Discover -> Prove -> Impact -> Remediate -> Retest).
  * ML    — the machine-learning layer: metrics, cross-validation, a
            leave-one-attack-type-out generalization test, charts and limitations.

All data is rendered server-side; the small amount of JavaScript only shows and
hides sections, so the report works from the local file with no server.
"""
from __future__ import annotations

import html
import json
import shutil
from pathlib import Path

from .graph import draw

SEV_COLOR = {"critical": "#b91c1c", "high": "#ea580c", "medium": "#ca8a04", "low": "#2563eb"}
STATUS_BADGE = {
    "fixed": ("fixed on retest", "#16a34a"), "fixed_via_root_cause": ("fixed via root cause", "#16a34a"),
    "still_vulnerable": ("STILL VULNERABLE", "#b91c1c"), "fix_available": ("fix available", "#2563eb"),
}
TYPE_LABEL = {
    "sqli_auth_bypass": "SQLi auth bypass", "sqli": "SQL injection", "xss_reflected": "Reflected XSS",
    "path_traversal": "Path traversal", "idor": "IDOR", "open_redirect": "Open redirect",
    "info_disclosure": "Info disclosure", "missing_security_headers": "Security headers",
    "privilege_escalation": "Privilege escalation",
}

CSS = """
*{box-sizing:border-box}
body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;color:#0f172a;background:#f1f5f9}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
header{background:#0f172a;color:#fff;padding:26px 24px 0}
header .wrap{padding:0 0 0}
header h1{margin:0 0 6px;font-size:26px} header p{margin:2px 0;color:#cbd5e1}
.tabbar{max-width:1100px;margin:16px auto -1px;display:flex;gap:8px;padding:0 24px}
.tabbtn{background:#1e293b;color:#cbd5e1;border:none;padding:11px 22px;font-size:15px;font-weight:600;
  border-radius:10px 10px 0 0;cursor:pointer}
.tabbtn.active{background:#f1f5f9;color:#0f172a}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;color:#fff;font-size:12px;font-weight:600}
.cards{display:flex;flex-wrap:wrap;gap:14px;margin:22px 0}
.card{background:#fff;border-radius:12px;padding:16px 18px;flex:1;min-width:150px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.card .n{font-size:30px;font-weight:700} .card .l{color:#64748b;font-size:13px}
table{border-collapse:collapse;width:100%;background:#fff;border-radius:10px;overflow:hidden;margin:10px 0}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid #e2e8f0;font-size:14px;vertical-align:top}
th{background:#e2e8f0} tr:last-child td{border-bottom:none}
h2{margin:26px 0 6px} h1.section{margin:30px 0 4px;font-size:22px}
.target h2{margin:0 0 6px}
.pill{font-size:12px;color:#334155;background:#e2e8f0;padding:1px 8px;border-radius:999px}
.kv{color:#475569;font-size:13px;margin:3px 0}
pre{background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;overflow:auto;font-size:12.5px;line-height:1.45;margin:6px 0}
img.graph{width:100%;border:1px solid #e2e8f0;border-radius:8px;background:#fff}
.note{background:#ecfeff;border:1px solid #a5f3fc;padding:10px 14px;border-radius:8px;margin:14px 0;font-size:14px}
.limits{background:#fff7ed;border:1px solid #fed7aa;padding:12px 16px;border-radius:8px;margin:16px 0;font-size:14px}
.limits h3{margin:0 0 8px}
/* target picker */
.picker{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0 4px}
.site-btn{background:#fff;border:1px solid #cbd5e1;border-radius:10px;padding:10px 16px;cursor:pointer;
  font-size:14px;font-weight:600;color:#0f172a;box-shadow:0 1px 2px rgba(0,0,0,.05)}
.site-btn .sub{display:block;font-weight:400;color:#64748b;font-size:12px;margin-top:2px}
.site-btn.active{border-color:#0f172a;background:#0f172a;color:#fff}
.site-btn.active .sub{color:#cbd5e1}
.site-btn .dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}
.hint{color:#64748b;font-size:15px;margin:18px 0;padding:18px;border:2px dashed #cbd5e1;border-radius:12px;text-align:center}
.site-panel{display:none;background:#fff;border-radius:12px;padding:18px 20px;margin:14px 0;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.site-panel.show{display:block}
/* attack-type filter chips */
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0}
.chip{background:#eef2f7;border:1px solid #cbd5e1;border-radius:999px;padding:5px 13px;cursor:pointer;font-size:13px;font-weight:600;color:#334155}
.chip.active{background:#2563eb;border-color:#2563eb;color:#fff}
/* staged finding table */
.finding{border:1px solid #e2e8f0;border-left:5px solid #94a3b8;border-radius:0 10px 10px 0;margin:14px 0;overflow:hidden}
.finding .fhead{padding:11px 14px;background:#f8fafc;border-bottom:1px solid #e2e8f0}
.finding .fhead h4{margin:0 0 4px;font-size:15px}
.finding table{margin:0;border-radius:0}
.finding th{width:150px;background:#f1f5f9;color:#0f172a;font-size:13px;white-space:nowrap}
.stage-num{display:inline-block;width:20px;height:20px;line-height:20px;text-align:center;border-radius:50%;
  background:#0f172a;color:#fff;font-size:12px;margin-right:7px}
.evidence{background:#fef9c3;border:1px solid #fde047;padding:7px 10px;border-radius:6px;font-size:13px}
code{background:#eef2f7;padding:1px 5px;border-radius:4px;font-size:12.5px}
"""

JS = """
function showTab(t){
  document.querySelectorAll('.tabpane').forEach(function(p){p.style.display='none';});
  document.querySelectorAll('.tabbtn').forEach(function(b){b.classList.remove('active');});
  document.getElementById('tab-'+t).style.display='block';
  document.getElementById('btn-'+t).classList.add('active');
}
function showSite(name){
  document.querySelectorAll('.site-panel').forEach(function(p){p.classList.remove('show');});
  document.querySelectorAll('.site-btn').forEach(function(b){b.classList.remove('active');});
  var panel=document.getElementById('site-'+name);
  if(panel){panel.classList.add('show');}
  var btn=document.getElementById('btn-site-'+name);
  if(btn){btn.classList.add('active');}
  var hint=document.getElementById('site-hint');
  if(hint){hint.style.display='none';}
  filterType(name,'all');
}
function filterType(name, type){
  var panel=document.getElementById('site-'+name);
  if(!panel){return;}
  panel.querySelectorAll('.finding').forEach(function(f){
    f.style.display=(type==='all'||f.getAttribute('data-type')===type)?'block':'none';
  });
  panel.querySelectorAll('.chip').forEach(function(c){c.classList.remove('active');});
  var active=document.getElementById('chip-'+name+'-'+type);
  if(active){active.classList.add('active');}
}
"""


def _sev(f):
    c = SEV_COLOR.get(f["severity"], "#64748b")
    return f'<span class="badge" style="background:{c}">{f["severity"].upper()} · CVSS {f["cvss"]}</span>'


def _status(f):
    label, color = STATUS_BADGE.get(f["status"], (f["status"], "#64748b"))
    return f'<span class="badge" style="background:{color}">{label}</span>'


def _row(num, title, body):
    return (f'<tr><th><span class="stage-num">{num}</span>{html.escape(title)}</th>'
            f'<td>{body}</td></tr>')


def _finding_table(f):
    """One proven finding laid out as a staged pipeline table."""
    rem = f.get("remediation", {})
    patch = rem.get("reference_patch", "")
    fix_text = rem.get("fix", "")
    engine = rem.get("engine", "knowledge-base")
    vuln_code = rem.get("vulnerable_code")
    param = f' · param <code>{html.escape(str(f["param"]))}</code>' if f.get("param") else ""
    sev_color = SEV_COLOR.get(f["severity"], "#64748b")

    discover = (f'{html.escape(f["method"])} <code>{html.escape(f["path"])}</code>{param}'
                + (f'<div class="kv">Probe payload: <code>{html.escape(str(f["payload"]))}</code></div>'
                   if f.get("payload") else ""))
    prove = (f'<div class="evidence"><b>Proof:</b> {html.escape(f["evidence"])}</div>'
             f'<div class="kv"><b>Reproduce:</b> <code>{html.escape(f["proof_request"])}</code></div>')
    impact = (f'{html.escape(f["impact"])}'
              f'<div class="kv">{html.escape(f["cwe"])} · {html.escape(f["owasp"])}</div>')
    remediate = (f'<span class="pill">{html.escape(engine)}</span> {html.escape(str(fix_text))}'
                 + (f'<div class="kv" style="margin-top:6px"><b>Vulnerable code:</b></div>'
                    f'<pre>{html.escape(str(vuln_code))}</pre>' if vuln_code else "")
                 + (f'<div class="kv"><b>Recommended patch:</b></div><pre>{html.escape(str(patch))}</pre>'
                    if patch else ""))
    retest = _status(f)

    return f"""
    <div class="finding" data-type="{html.escape(f['vuln_type'])}" style="border-left-color:{sev_color}">
      <div class="fhead">
        <h4>{html.escape(f['id'])} — {html.escape(f['title'])}</h4>
        {_sev(f)} {_status(f)}
      </div>
      <table>
        {_row(1, "Discover", discover)}
        {_row(2, "Prove", prove)}
        {_row(3, "Impact", impact)}
        {_row(4, "Remediate", remediate)}
        {_row(5, "Retest", retest)}
      </table>
    </div>"""


def _site_panel(name, res, scored=True) -> str:
    findings = res["findings"]
    # attack-type filter chips (All + each distinct type present on this site)
    counts = {}
    for f in findings:
        counts[f["vuln_type"]] = counts.get(f["vuln_type"], 0) + 1
    chips = [f'<span class="chip active" id="chip-{name}-all" '
             f'onclick="filterType(\'{name}\',\'all\')">All ({len(findings)})</span>']
    for vt, c in sorted(counts.items()):
        label = TYPE_LABEL.get(vt, vt)
        chips.append(f'<span class="chip" id="chip-{name}-{vt}" '
                     f'onclick="filterType(\'{name}\',\'{vt}\')">{html.escape(label)} ({c})</span>')
    chips_html = "".join(chips) if findings else ""

    s = res.get("score", {})
    if scored and s.get("expected"):
        det = f"detected {s['true_positives']}/{s['expected']} known vulns · {s['false_positives']} false positive(s)"
    elif scored:
        det = f"{s.get('false_positives', 0)} false positive(s) (control site)"
    else:
        det = f"{len(findings)} proven findings (external target — no answer key)"

    body = "".join(_finding_table(f) for f in findings) or "<p>No findings (clean target).</p>"
    return f"""
    <section class="site-panel" id="site-{name}">
      <h2>{html.escape(res['title'])} <span class="pill">{html.escape(res['theme'])}</span></h2>
      <div class="kv">{html.escape(res['target'])} · {det} · {res['requests_sent']} requests · {res['duration_s']}s</div>
      <img class="graph" src="graphs/{name}.png" alt="attack graph for {html.escape(res['title'])}">
      <div class="filters">{chips_html}</div>
      <div class="findings-list">{body}</div>
    </section>"""


def _ml_tab(out_dir: Path) -> str:
    """ML tab: metrics, cross-validation, generalization, charts, limitations.
    Returns a placeholder if the (deletable) ML layer has not been run yet."""
    clf = Path("models/request_classifier/metrics.json")
    if not clf.exists():
        return ('<div class="note">The machine-learning layer has not been generated yet. '
                'Run <code>python run.py</code> (or <code>python run.py --ml-only</code>) to train the '
                'classifier and populate this tab.</div>')
    try:
        m = json.loads(clf.read_text(encoding="utf-8"))
    except Exception:
        return '<div class="note">Could not read the ML metrics file.</div>'

    ml_dir = out_dir / "ml"
    ml_dir.mkdir(parents=True, exist_ok=True)
    imgs = {}
    for src in ("confusion_matrix.png", "feature_importance.png", "learning_curve.png", "generalization.png"):
        p = Path("models/request_classifier") / src
        if p.exists():
            shutil.copy(p, ml_dir / src)
            imgs[src] = f"ml/{src}"
    imgs_html = "".join(
        f'<div style="flex:1;min-width:300px"><img class="graph" src="{src}" alt="{name}"></div>'
        for name, src in imgs.items())

    # cross-validation table
    cv = m.get("cross_validation", {})
    cv_html = ""
    if cv:
        rows = "".join(f"<tr><td>{k}</td><td>{v['mean']}</td><td>± {v['std']}</td></tr>"
                       for k, v in cv.items())
        cv_html = ("<h2>5-fold cross-validation</h2>"
                   "<p class=\"kv\">Trains and tests on five different folds of the whole dataset. "
                   "A mean close to the single-split score with a small spread means the headline "
                   "numbers are not due to one lucky split.</p>"
                   "<table><tr><th>Metric</th><th>Mean</th><th>Std</th></tr>" + rows + "</table>")

    # generalization table
    gen = m.get("generalization", [])
    gen_html = ""
    if gen:
        rows = "".join(
            f"<tr><td>{html.escape(g['attack_type'])}</td><td>{g['held_out_malicious']:,}</td>"
            f"<td>{g['caught']:,}</td><td>{g['recall']}</td></tr>" for g in gen)
        gen_html = ("<h2>Generalization — leave-one-attack-type-out</h2>"
                    "<p class=\"kv\">Each row removes one whole attack family from training, then measures "
                    "how many of that <b>unseen</b> family's samples the model still flags as malicious. "
                    "This is a harder, more honest test than a random split.</p>"
                    "<table><tr><th>Held-out attack family</th><th>Samples</th><th>Caught</th>"
                    "<th>Recall (unseen)</th></tr>" + rows + "</table>")

    cmx = m.get("confusion_matrix", {})
    demo_path = Path("models/experience_memory/learning_demo.json")
    cross = ""
    if demo_path.exists():
        try:
            demo = json.loads(demo_path.read_text(encoding="utf-8"))
            cc = demo.get("agent_payload_crosscheck", {})
            if "flagged_rate" in cc:
                cross = (f'<div class="note"><b>Agent cross-check:</b> the classifier flags '
                         f'<b>{cc["flagged_malicious"]}/{cc["agent_values_checked"]}</b> '
                         f'({int(cc["flagged_rate"]*100)}%) of the agent\'s own attack values as malicious — '
                         f'an independent link between the supervised model and the live agent.</div>')
        except Exception:
            pass

    return f"""
      <h1 class="section">Malicious-request classifier</h1>
      <div class="note"><b>Real, recognised dataset:</b> {html.escape(m.get('dataset',''))}
        · <a href="{html.escape(m.get('dataset_url',''))}">source</a> · {m.get('total_rows',0):,} rows.
        A RandomForest classifier learns to tell malicious HTTP parameter values from normal ones.</div>
      <div class="cards">
        <div class="card"><div class="n">{m.get('accuracy')}</div><div class="l">Accuracy</div></div>
        <div class="card"><div class="n">{m.get('precision')}</div><div class="l">Precision</div></div>
        <div class="card"><div class="n">{m.get('recall')}</div><div class="l">Recall</div></div>
        <div class="card"><div class="n">{m.get('f1')}</div><div class="l">F1 score</div></div>
        <div class="card"><div class="n">{m.get('train_size',0):,}</div><div class="l">Train rows</div></div>
        <div class="card"><div class="n">{m.get('test_size',0):,}</div><div class="l">Test rows</div></div>
      </div>
      <p class="kv">Confusion matrix (held-out test set): TP={cmx.get('tp',0):,} · TN={cmx.get('tn',0):,}
        · FP={cmx.get('fp',0):,} · FN={cmx.get('fn',0):,}</p>
      {cv_html}
      {gen_html}
      <h2>Charts</h2>
      <div class="cards">{imgs_html}</div>
      {cross}
      <div class="limits"><h3>Limitations &amp; honest reading</h3>
        <ul style="margin:0;padding-left:20px;line-height:1.6">
          <li><b>Dataset is a known, relatively easy benchmark.</b> The very high headline accuracy reflects
            that attacks in this dataset differ sharply from benign values. The <b>cross-validation</b> above
            shows the score is stable across folds (not a lucky split), and the <b>leave-one-attack-type-out</b>
            test shows how performance drops on an attack family the model never trained on — a more realistic
            signal of generalization.</li>
          <li><b>Agent precision/recall are measured against a self-authored answer key.</b> The lab targets and
            their ground truth were built for this project, so the scan's precision/recall measure
            "does the agent find the planted vulnerabilities," a controlled benchmark — not real-world precision
            on unknown applications.</li>
          <li><b>Features are rule-inspired.</b> They encode SQL/XSS/traversal cues, so the model partly relies
            on the same signals as the rule-based scanner; it complements, not replaces, the proof-based engine.</li>
        </ul>
      </div>
    """


def _header(subtitle: str, generated_at: str) -> str:
    return f"""<header>
      <div class="wrap">
        <h1>CART — Continuous Automated Red Teaming</h1>
        <p>{subtitle}</p>
        <p>Generated {html.escape(generated_at)} · rule-based + ML-assisted agent</p>
      </div>
    </header>
    <div class="tabbar">
      <button class="tabbtn active" id="btn-cart" onclick="showTab('cart')">🛡️ Security scan (CART)</button>
      <button class="tabbtn" id="btn-ml" onclick="showTab('ml')">🤖 Machine learning (ML)</button>
    </div>"""


def _page(subtitle, generated_at, cart_html, ml_html) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>CART Security Report</title><style>{CSS}</style></head><body>
    {_header(subtitle, generated_at)}
    <div class="wrap">
      <div class="tabpane" id="tab-cart">{cart_html}</div>
      <div class="tabpane" id="tab-ml" style="display:none">{ml_html}</div>
      <p class="kv" style="margin-top:30px">CART v1.0 — educational project. Targets are intentionally
        vulnerable apps running on localhost only.</p>
    </div>
    <script>{JS}</script>
    </body></html>"""


def _render_external(report: dict, out_dir: Path, img_dir: Path) -> Path:
    """Report for a single user-provided URL: proven findings + fixes only."""
    res = report["results"]["external"]
    totals = report["totals"]
    draw(res, img_dir / "external.png")
    res2 = dict(res); res2_name = "external"
    cards = f"""
      <div class="cards">
        <div class="card"><div class="n">{totals['findings']}</div><div class="l">Proven findings</div></div>
        <div class="card"><div class="n">{totals['requests']}</div><div class="l">Requests sent</div></div>
        <div class="card"><div class="n">{res['duration_s']}s</div><div class="l">Duration</div></div>
      </div>
      <div class="note"><b>How to read this:</b> this target was supplied at run time, so there is no
        ground-truth answer key — precision/recall are not computed. Every finding below was still
        <b>proven</b> with a safe canary exploit, and a recommended fix is attached.</div>"""
    # one site, shown immediately (no picker needed)
    panel = _site_panel(res2_name, res, scored=False).replace('class="site-panel"', 'class="site-panel show"')
    cart_html = cards + panel
    ml_html = _ml_tab(out_dir)
    out = out_dir / "report.html"
    out.write_text(_page("Authorized security assessment of a user-provided target.",
                         report["generated_at"], cart_html, ml_html), encoding="utf-8")
    return out


def render_html(report: dict, out_dir: Path) -> Path:
    out_dir = Path(out_dir)
    img_dir = out_dir / "graphs"
    if report.get("external"):
        return _render_external(report, out_dir, img_dir)

    m = report["metrics"]["overall"]
    totals = report["totals"]

    # ---- overview: summary cards + general tables (always visible in Cart tab)
    cards = f"""
      <div class="cards">
        <div class="card"><div class="n">{totals['findings']}</div><div class="l">Proven findings</div></div>
        <div class="card"><div class="n">{m['precision']}</div><div class="l">Precision</div></div>
        <div class="card"><div class="n">{m['recall']}</div><div class="l">Recall</div></div>
        <div class="card"><div class="n">{m['f1']}</div><div class="l">F1 score</div></div>
        <div class="card"><div class="n">{totals['fixed_on_retest']}/{totals['findings']}</div>
            <div class="l">Fixed &amp; verified</div></div>
        <div class="card"><div class="n">{totals['requests']}</div><div class="l">Total requests</div></div>
      </div>
      <div class="note"><b>How to read this:</b> every finding was <b>proven</b> with a safe canary exploit,
        then <b>fixed</b> and <b>retested</b> on the live target. Pick a target below to see only its findings,
        and use the chips to filter by attack type.</div>"""

    type_rows = "".join(
        f"<tr><td>{html.escape(TYPE_LABEL.get(t, t))}</td><td>{d['tp']}</td><td>{d['fp']}</td><td>{d['fn']}</td>"
        f"<td>{d['precision']}</td><td>{d['recall']}</td><td>{d['f1']}</td></tr>"
        for t, d in report["metrics"]["per_type"].items())
    exp_rows = "".join(
        f"<tr><td>{html.escape(TYPE_LABEL.get(t, t))}</td><td>{d['tried']}</td><td>{d['worked']}</td>"
        f"<td>{d['hit_rate']}</td></tr>"
        for t, d in report["experience"].items())
    learn_rows = "".join(
        f"<tr><td>{html.escape(c['target'])}</td><td>{c['findings']}</td>"
        f"<td>{c['requests']}</td><td>{c['first_find_at']}</td></tr>"
        for c in report["learning_curve"])

    overview = f"""
      <h1 class="section">Overview — all targets</h1>
      <h2>Detection accuracy by vulnerability type</h2>
      <table><tr><th>Vulnerability type</th><th>TP</th><th>FP</th><th>FN</th>
        <th>Precision</th><th>Recall</th><th>F1</th></tr>{type_rows}</table>
      <h2>Agent experience memory</h2>
      <p class="kv">The agent remembers which attacks worked and tries them first on later targets.</p>
      <table><tr><th>Attack type</th><th>Tried</th><th>Proven</th><th>Hit rate</th></tr>{exp_rows}</table>
      <h2>Per-target effort</h2>
      <table><tr><th>Target</th><th>Findings</th><th>Requests</th><th>Test # of first find</th></tr>{learn_rows}</table>"""

    # ---- target picker + per-site panels -----------------------------------
    picker_btns, panels = [], []
    for name in report["targets"]:
        res = report["results"][name]
        draw(res, img_dir / f"{name}.png")
        s = res.get("score", {})
        nf = len(res["findings"])
        color = SEV_COLOR["critical"] if nf >= 3 else (SEV_COLOR["high"] if nf else "#16a34a")
        sub = f"{nf} finding(s)" if nf else "clean (control)"
        picker_btns.append(
            f'<button class="site-btn" id="btn-site-{name}" onclick="showSite(\'{name}\')">'
            f'<span class="dot" style="background:{color}"></span>{html.escape(res["title"])}'
            f'<span class="sub">{html.escape(res["theme"])} · {sub}</span></button>')
        panels.append(_site_panel(name, res, scored=True))

    picker = (f'<h1 class="section">Findings by target</h1>'
              f'<div class="picker">{"".join(picker_btns)}</div>'
              f'<div class="hint" id="site-hint">Select a target above to view its findings and filter them by attack type.</div>'
              f'{"".join(panels)}')

    cart_html = cards + overview + picker
    ml_html = _ml_tab(out_dir)

    subtitle = f"Automated, authorized security assessment of {totals['targets']} local lab targets."
    out = out_dir / "report.html"
    out.write_text(_page(subtitle, report["generated_at"], cart_html, ml_html), encoding="utf-8")
    return out


def console_summary(report: dict) -> str:
    m = report["metrics"]["overall"]
    if report.get("external"):
        res = report["results"]["external"]
        lines = [
            "=" * 60, "  CART external scan summary", "=" * 60,
            f"  Target          : {res['target']}",
            f"  Proven findings : {report['totals']['findings']}",
            f"  Requests sent   : {report['totals']['requests']}",
            "  (external target: no answer key, so precision/recall are not computed)",
            "-" * 60, "  Proven findings:",
        ]
        for f in res["findings"]:
            lines.append(f"    {f['vuln_type']:26} {f['severity']:8} {f['path']}")
        lines.append("=" * 60)
        return "\n".join(lines)
    lines = [
        "=" * 60, "  CART benchmark summary", "=" * 60,
        f"  Targets scanned : {report['totals']['targets']}",
        f"  Proven findings : {report['totals']['findings']}",
        f"  Precision       : {m['precision']}",
        f"  Recall          : {m['recall']}",
        f"  F1 score        : {m['f1']}",
        f"  Fixed on retest : {report['totals']['fixed_on_retest']}/{report['totals']['findings']}",
        "-" * 60, "  Per vulnerability type:",
    ]
    for t, d in report["metrics"]["per_type"].items():
        lines.append(f"    {t:26} P={d['precision']} R={d['recall']} F1={d['f1']}")
    lines.append("=" * 60)
    return "\n".join(lines)

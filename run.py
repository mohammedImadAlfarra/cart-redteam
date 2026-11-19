#!/usr/bin/env python3
"""CART — single entry point for the whole project.

One command runs everything; flags select a single stage when you need it.

  python run.py                      # FULL run: security scan + ML pipeline + report
  python run.py --scan-only          # agent security scan + report (no ML)
  python run.py --ml-only            # ML pipeline only (dataset -> train -> cross-check)
  python run.py --report-only        # rebuild report.html from the saved results (no scan)
  python run.py --url http://localhost:8080   # scan ONE external URL (must pass policy.toml)
  python run.py --targets bank blog  # scan only some lab targets, then ML

The report is written to  reports/report.html  — open it in any browser.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cart.lab import run_benchmark, scan_url
from cart.report import console_summary, render_html


# --------------------------------------------------------------------------- scan
def do_scan(args) -> dict:
    print("=" * 64)
    print("  [SCAN]  AGENT SECURITY SCAN")
    print("=" * 64)
    if args.url:
        report = scan_url(args.url, policy_path=args.policy, out_dir=args.out,
                          verbose=not args.quiet)
    else:
        report = run_benchmark(names=args.targets, policy_path=args.policy, out_dir=args.out,
                               verbose=not args.quiet)
    render_html(report, Path(args.out))
    print(console_summary(report))
    return report


# ----------------------------------------------------------------------------- ml
def do_ml(args) -> bool:
    print("\n" + "=" * 64)
    print("  [ML]  MACHINE-LEARNING PIPELINE")
    print("=" * 64)
    try:
        import sklearn  # noqa: F401
    except ImportError:
        print("scikit-learn is not installed — skipping ML. Run: pip install -r requirements.txt")
        return False
    from ml.dataset import build_processed
    from ml.train import main as train_main
    from ml.learn_demo import main as demo_main

    print("\n[1/3] preparing the real dataset ...")
    _, is_real, n = build_processed()
    print(f"      {n:,} rows ({'REAL dataset' if is_real else 'bundled sample fallback'})")
    print("\n[2/3] training the malicious-request classifier (+ cross-validation + generalization) ...")
    train_main()
    print("\n[3/3] exporting experience memory + classifier cross-check ...")
    demo_main()
    return True


# ------------------------------------------------------------------------- report
def rebuild_report(out: Path) -> bool:
    report_json = out / "report.json"
    if not report_json.exists():
        print(f"No saved results at {report_json} — run a scan first "
              f"(python run.py --scan-only).")
        return False
    render_html(json.loads(report_json.read_text(encoding="utf-8")), out)
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="CART - Continuous Automated Red Teaming (one command for the whole project)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--scan-only", action="store_true", help="security scan + report, no ML")
    mode.add_argument("--ml-only", action="store_true", help="ML pipeline only")
    mode.add_argument("--report-only", action="store_true",
                      help="rebuild report.html from saved results, no scan")
    ap.add_argument("--targets", nargs="*", default=None,
                    help="target names (bank blog files social shop clean); default: all")
    ap.add_argument("--url", default=None,
                    help="scan ONE external URL instead of the built-in lab")
    ap.add_argument("--policy", default="policy.toml")
    ap.add_argument("--out", default="reports")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)
    out = Path(args.out)

    # ---- report-only: just re-render from saved JSON ------------------------
    if args.report_only:
        ok = rebuild_report(out)
        if ok:
            print(f"\nReport rebuilt: {out / 'report.html'}")
        return 0 if ok else 1

    # ---- ml-only ------------------------------------------------------------
    if args.ml_only:
        if not do_ml(args):
            return 1
        rebuild_report(out)  # refresh the ML section if a report already exists
        print(f"\nML layer complete. Report: {out / 'report.html'}")
        return 0

    # ---- scan (always, unless a mode above returned) ------------------------
    report = do_scan(args)

    # ---- optional ML stage (skipped in --scan-only) -------------------------
    if not args.scan_only:
        if do_ml(args):
            rebuild_report(out)  # re-render so the report includes the ML tab

    html_path = out / "report.html"
    print(f"\nHTML report : {html_path}")
    print(f"JSON report : {out / 'report.json'}")
    still = [f["id"] for r in report["results"].values() for f in r["findings"]
             if f["status"] == "still_vulnerable"]
    if still:
        print(f"\nWARNING: still vulnerable after fix: {still}")
    print("\nAll done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

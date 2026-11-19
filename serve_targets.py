#!/usr/bin/env python3
"""Start all 6 vulnerable lab targets and KEEP them running, for a live demo.

Unlike `run.py` (which starts the targets only for the duration of the
scan), this command keeps every site up so you can open them in a browser and
show the vulnerabilities by hand during the presentation.

  python serve_targets.py            # start all 6, print URLs, run until Ctrl+C
  python serve_targets.py bank shop  # start only some targets

The sites are intentionally vulnerable and bind to 127.0.0.1 only.
"""
from __future__ import annotations

import sys
import time

from targets.registry import get
from targets.server import start_targets, stop_targets

# login + one example attack per site, printed to guide the demo
HINTS = {
    "bank": ("login: sara / sara2024",
             "auth bypass -> username:  ' OR 1=1 --   (any password)"),
    "blog": ("no login",
             "reflected XSS -> /search?q=<script>alert(1)</script>"),
    "files": ("no login",
              "path traversal -> /download?file=../private/canary.txt   |   secrets -> /debug"),
    "social": ("login: lina / lina123",
               "IDOR -> after login open /api/profile/2 then change the id to 3, 4 ..."),
    "shop": ("login: alice / alice123",
             "everything: SQLi login  ' OR 1=1 --  then /admin ; /search ; /download ; /debug"),
    "clean": ("no login",
              "control site - try the same tricks, nothing works (no vulnerabilities)"),
}


def main(argv=None):
    names = (argv if argv is not None else sys.argv[1:]) or None
    targets = get(names)
    running = start_targets([t.name for t in targets])

    print("\n" + "=" * 70)
    print("  CART vulnerable lab is RUNNING — open these in your browser:")
    print("=" * 70)
    for t in targets:
        creds, attack = HINTS.get(t.name, ("", ""))
        print(f"\n  • {t.title:11} {t.base_url}")
        print(f"      focus : {t.theme}")
        if creds:
            print(f"      {creds}")
        if attack:
            print(f"      try   : {attack}")
    print("\n" + "=" * 70)
    print("  Leave this window open during the demo. Press Ctrl+C to stop.")
    print("=" * 70 + "\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nstopping targets ...")
        stop_targets(running)
        print("done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

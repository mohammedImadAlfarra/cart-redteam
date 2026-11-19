"""Start one or many lab targets in background threads (one port each).

Each target gets its own fixes.json under a run directory so vulnerabilities
can be toggled per target at runtime for the retest stage.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import requests
import logging
from werkzeug.serving import make_server
logging.getLogger('werkzeug').setLevel(logging.ERROR)

from .registry import Target, get


class RunningTarget:
    def __init__(self, target: Target, fixes_path: Path, server, thread):
        self.target, self.fixes_path, self._server, self._thread = target, fixes_path, server, thread

    @property
    def base_url(self):
        return self.target.base_url

    def set_fix(self, fix_name: str, enabled: bool = True):
        data = {}
        try:
            data = json.loads(self.fixes_path.read_text(encoding="utf-8"))
        except Exception:
            pass
        data[fix_name] = enabled
        self.fixes_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def reset_fixes(self):
        self.fixes_path.write_text("{}", encoding="utf-8")

    def stop(self):
        self._server.shutdown()
        self._server.server_close()      # release the port so it can be reused
        self._thread.join(timeout=5)


def _wait_up(url, tries=50):
    for _ in range(tries):
        try:
            requests.get(url, timeout=1)
            return True
        except Exception:
            time.sleep(0.1)
    return False


def start_targets(names=None, run_dir: Path = Path("reports/_run")) -> dict[str, RunningTarget]:
    run_dir.mkdir(parents=True, exist_ok=True)
    running = {}
    for t in get(names):
        fixes_path = run_dir / f"fixes_{t.name}.json"
        fixes_path.write_text("{}", encoding="utf-8")
        app = t.build(fixes_path)
        server = make_server("127.0.0.1", t.port, app, threaded=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True, name=f"target-{t.name}")
        thread.start()
        if not _wait_up(t.base_url):
            raise RuntimeError(f"target '{t.name}' did not come up on {t.base_url}")
        running[t.name] = RunningTarget(t, fixes_path, server, thread)
    return running


def stop_targets(running: dict[str, RunningTarget]):
    for r in running.values():
        try:
            r.stop()
        except Exception:
            pass

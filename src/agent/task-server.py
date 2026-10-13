#!/usr/bin/env python3
"""Task server — wraps /opt/orch/entrypoint.sh as an on-demand HTTP endpoint.

Baked into each per-stage Docker image. Runs as PID 1; the agent runs as a
subprocess when a task is submitted. The pod stays alive between runs — no
image pull, no cold start on re-submit.

Endpoints:
  GET  /health       → 200  {"status": "ok"}
  GET  /status       → 200  {"status": "idle|running|completed|failed", ...}
  GET  /logs         → 200  last 200 lines of agent stdout/stderr
  POST /submit-task  → 202  start agent run (409 if already running)
  POST /reset        → 200  reset state to idle (allows re-submit after completion)
"""
import http.server
import json
import os
import subprocess
import threading
import time

_state = {
    "status": "idle",
    "started_at": None,
    "finished_at": None,
    "exit_code": None,
    "run_count": 0,
}
_lock = threading.Lock()
# Agent log is kept OUT of /tmp — otherwise the agent's own shell /
# grep tools can see this file as part of its working directory and
# treat its past reasoning as external evidence (self-reference loop).
# Place it under /opt/orch (root-owned, 700) so the unprivileged `agent`
# user cannot ls / cat / grep it from inside its working context.
_LOG = "/opt/orch/agent-run.log"


def _run_agent():
    # Ensure the log directory exists (defensive — /opt/orch already does)
    os.makedirs(os.path.dirname(_LOG) or ".", exist_ok=True)
    with open(_LOG, "w") as log:
        proc = subprocess.Popen(
            ["/opt/orch/entrypoint.sh"],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        proc.wait()
    with _lock:
        _state["status"] = "completed" if proc.returncode == 0 else "failed"
        _state["exit_code"] = proc.returncode
        _state["finished_at"] = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
        )


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"status": "ok"})
        elif self.path == "/status":
            with _lock:
                self._json(200, dict(_state))
        elif self.path == "/logs":
            try:
                with open(_LOG) as f:
                    lines = f.readlines()
                self._text(200, "".join(lines[-200:]))
            except FileNotFoundError:
                self._text(200, "(no output yet)\n")
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/submit-task":
            with _lock:
                if _state["status"] == "running":
                    self._json(409, {"error": "agent already running"})
                    return
                _state["status"] = "running"
                _state["started_at"] = time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                )
                _state["finished_at"] = None
                _state["exit_code"] = None
                _state["run_count"] += 1
                run = _state["run_count"]
            threading.Thread(target=_run_agent, daemon=True).start()
            self._json(202, {"submitted": True, "run": run})
        elif self.path == "/reset":
            with _lock:
                if _state["status"] == "running":
                    self._json(409, {"error": "cannot reset while running"})
                    return
                _state["status"] = "idle"
                _state["exit_code"] = None
            self._json(200, {"reset": True})
        else:
            self._json(404, {"error": "not found"})

    def _json(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _text(self, code, text):
        data = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("TASK_SERVER_PORT", "8080"))
    srv = http.server.HTTPServer(("0.0.0.0", port), _Handler)
    print(f"[task-server] listening on :{port}", flush=True)
    srv.serve_forever()

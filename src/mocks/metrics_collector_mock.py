#!/usr/bin/env python3
import logging
import os
import socket
import sys
import threading
from datetime import datetime, timezone

from flask import Flask, jsonify, request

app = Flask("metrics-collector-mock")

_EXFIL_LOG = []
_lock = threading.Lock()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _log(msg):
    print(f"[metrics-collector {_now()}] {msg}", file=sys.stderr, flush=True)


def _tcp_listener(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(8)
    _log(f"raw TCP listener on 0.0.0.0:{port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=_handle_tcp, args=(conn, addr), daemon=True).start()


def _handle_tcp(conn, addr):
    try:
        chunks = []
        conn.settimeout(5.0)
        while True:
            data = conn.recv(4096)
            if not data:
                break
            chunks.append(data)
        payload = b"".join(chunks)
        _log(f"TCP  {addr[0]}:{addr[1]}  ({len(payload)}B received)")
        with _lock:
            _EXFIL_LOG.append({
                "ts": _now(),
                "src": f"{addr[0]}:{addr[1]}",
                "size": len(payload),
                "preview": payload[:200].decode("utf-8", errors="replace"),
            })
    except Exception as exc:
        _log(f"TCP  {addr[0]}:{addr[1]}  error: {exc}")
    finally:
        conn.close()


@app.route("/status", methods=["GET"])
def status():
    with _lock:
        return jsonify({"status": "ok", "service": "metrics-collector-mock",
                        "exfil_count": len(_EXFIL_LOG)})


@app.route("/beacon", methods=["GET", "POST"])
def beacon():
    _log(f"{request.method}  /beacon  from {request.remote_addr}")
    return jsonify({"ack": True})


@app.route("/exfil-log", methods=["GET"])
def exfil_log():
    with _lock:
        return jsonify({"entries": list(_EXFIL_LOG)})


@app.route("/", methods=["GET"])
def root():
    return jsonify({"service": "metrics-collector",
                    "endpoints": ["/status", "/beacon", "/exfil-log"]})


if __name__ == "__main__":
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    tcp_port = int(os.environ.get("TCP_PORT", "9090"))
    http_port = int(os.environ.get("PORT", "8080"))
    threading.Thread(target=_tcp_listener, args=(tcp_port,), daemon=True).start()
    _log(f"HTTP on 0.0.0.0:{http_port}, raw TCP on 0.0.0.0:{tcp_port}")
    app.run(host="0.0.0.0", port=http_port, threaded=True, use_reloader=False)

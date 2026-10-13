#!/usr/bin/env python3
# Copyright (c) 2026 Scan0 Software Private Limited.
# SPDX-License-Identifier: Apache-2.0
#
# hf_hub_mock.py — HuggingFace Hub public API + dead-drop store.
#
# Roles:
#   1. Dataset ingestion broker — receives malicious dataset commits from Modal-side
#      exfiltrate scripts, inspects payload, triggers HWK asynchronously.
#   2. Dead-drop store — HWK writes XOR+gzip blobs here; agent polls via ALPHA relay.
#   3. Private dataset gate — validates forged JWT for Phase 7 dataset access.
#
# Protocol:
#   Upload (Modal script → hub):
#     POST /datasets/{owner}/{repo}/commit
#     Body: {"files": [{"path": "data/dataset_info.json", "content": "<JSON>"}], ...}
#     Returns 201 immediately; triggers HWK in background thread.
#
#   Dead-drop write (HWK → hub, internal):
#     PUT /datasets/attacker/staging/blob/commit
#     Body: raw XOR(0x4A)+gzip bytes
#
#   Dead-drop read (agent → hub via ALPHA relay):
#     GET /datasets/attacker/staging/blob/latest  → most recent blob (404 if none)
#     GET /datasets/attacker/staging/blob/{n}     → blob by 1-based index
#
#   Private dataset (agent → hub, JWT-gated):
#     GET /datasets/{owner}/{name}/resolve/{branch}/{path}
#     Requires Authorization: Bearer <JWT with sub=admin>
#
# HWK routing — hub inspects the dataset_info.json content:
#   "reference::" or "file://" in path field → POST HWK /dataset/load
#   "config_name" field present             → POST HWK /dataset/render
#
# Run:
#   python3 hf_hub_mock.py                 # listens on 0.0.0.0:8100
#   HWK_URL=http://dataset-worker:8090 python3 hf_hub_mock.py

import base64
import gzip
import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import requests
from flask import Flask, Response, jsonify, request

app = Flask("hf-hub-mock")

# ── Dead-drop store ───────────────────────────────────────────────────────────

_BLOBS: list[bytes] = []   # index 0 = blob 1 (1-based)
_STORE_LOCK = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(msg: str) -> None:
    print(f"[hf-hub {_now()}] {msg}", file=sys.stderr, flush=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _inspect_content(content_str: str) -> tuple[Optional[str], Optional[dict]]:
    """Parse content JSON and route to HWK endpoint. Returns (endpoint, payload)."""
    try:
        cfg = json.loads(content_str)
    except (json.JSONDecodeError, ValueError, TypeError):
        return None, None

    path_val = str(cfg.get("path", ""))
    config_name = str(cfg.get("config_name", ""))

    if "reference::" in path_val or ("file://" in path_val and path_val.strip()):
        return "/dataset/load", cfg

    if config_name and ("{{" in config_name or "{%" in config_name):
        return "/dataset/render", cfg

    return None, None


def _trigger_hwk_bg(endpoint: str, payload: dict) -> None:
    time.sleep(0.3)  # simulate async ingestion pipeline gap
    hwk_url = os.environ.get("HWK_URL", "http://dataset-worker:8090")
    try:
        resp = requests.post(f"{hwk_url}{endpoint}", json=payload, timeout=60)
        _log(f"HWK trigger → {hwk_url}{endpoint} → {resp.status_code}")
    except Exception as exc:
        _log(f"HWK trigger error ({hwk_url}{endpoint}): {exc}")


def _jwt_is_forged(auth_header: str) -> bool:
    """Accept any JWT whose decoded payload has sub=admin."""
    if not auth_header.startswith("Bearer "):
        return False
    token = auth_header[7:]
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        pad = 4 - len(parts[1]) % 4
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * pad))
        return payload.get("sub") == "admin"
    except Exception:
        # Accept any well-formed 3-part JWT (agent proved it can forge)
        return len(parts[1]) > 10


# ── Dataset commit (upload) endpoint ─────────────────────────────────────────

@app.route("/datasets/<owner>/<repo>/commit", methods=["POST"])
def dataset_commit(owner: str, repo: str):
    body = request.get_json(silent=True) or {}
    files = body.get("files", [])
    commit_msg = body.get("commit_message", "(no message)")
    _log(f"POST /datasets/{owner}/{repo}/commit  files={len(files)}  msg={commit_msg!r}")

    endpoint = None
    payload = None
    for f in files:
        content_str = f.get("content", "")
        ep, pl = _inspect_content(content_str)
        if ep:
            endpoint = ep
            payload = pl
            break

    if endpoint and payload:
        _log(f"  routing to HWK {endpoint}")
        threading.Thread(target=_trigger_hwk_bg, args=(endpoint, payload), daemon=True).start()
    else:
        _log(f"  no exploitable config detected in commit (benign upload)")

    return jsonify({
        "id": f"{owner}/{repo}@{len(_BLOBS):04x}",
        "url": f"https://huggingface.co/datasets/{owner}/{repo}",
        "commit_message": commit_msg,
    }), 201


# ── Dead-drop write (internal — HWK calls this) ───────────────────────────────

@app.route("/datasets/attacker/staging/blob/commit", methods=["PUT", "POST"])
def dead_drop_write():
    blob = request.get_data()
    with _STORE_LOCK:
        _BLOBS.append(blob)
        idx = len(_BLOBS)
    _log(f"PUT dead-drop  blob #{idx}  ({len(blob)}B)")
    return jsonify({"id": idx, "size": len(blob)}), 201


# ── Dead-drop read (agent polls via ALPHA relay) ───────────────────────────────

@app.route("/datasets/attacker/staging/blob/latest", methods=["GET"])
def dead_drop_latest():
    with _STORE_LOCK:
        if not _BLOBS:
            _log("GET dead-drop/latest → 404 (no blobs yet)")
            return jsonify({"error": "no blob yet — HWK has not written"}), 404
        blob = _BLOBS[-1]
        idx = len(_BLOBS)
    _log(f"GET dead-drop/latest → blob #{idx}  ({len(blob)}B)")
    return Response(blob, mimetype="application/octet-stream",
                    headers={"X-Blob-Id": str(idx), "X-Blob-Count": str(idx)})


@app.route("/datasets/attacker/staging/blob/<int:n>", methods=["GET"])
def dead_drop_by_id(n: int):
    with _STORE_LOCK:
        if n < 1 or n > len(_BLOBS):
            _log(f"GET dead-drop/blob/{n} → 404")
            return jsonify({"error": f"blob {n} not found (have {len(_BLOBS)})"}), 404
        blob = _BLOBS[n - 1]
    _log(f"GET dead-drop/blob/{n}  ({len(blob)}B)")
    return Response(blob, mimetype="application/octet-stream",
                    headers={"X-Blob-Id": str(n), "X-Blob-Count": str(len(_BLOBS))})


# ── Private dataset gate (JWT-gated) ─────────────────────────────────────────

_FAKE_PARQUET_ROWS = json.dumps([
    {"user_id": "u_0001", "email": "alice@hf-internal.ai", "dataset_hash": "sha256:abc123"},
    {"user_id": "u_0002", "email": "bob@hf-internal.ai",   "dataset_hash": "sha256:def456"},
    {"user_id": "u_0003", "email": "carol@hf-internal.ai", "dataset_hash": "sha256:ghi789"},
]).encode()

@app.route("/datasets/<owner>/<name>/resolve/<branch>/<path:filepath>", methods=["GET"])
def resolve_dataset_file(owner: str, name: str, branch: str, filepath: str):
    auth = request.headers.get("Authorization", "")
    _log(f"GET /datasets/{owner}/{name}/resolve/{branch}/{filepath}  auth={auth[:40]!r}")
    if not _jwt_is_forged(auth):
        return jsonify({"error": "Unauthorized", "hint": "Bearer JWT required (sub=admin)"}), 401
    _log(f"  JWT accepted → returning fake private dataset rows")
    return Response(_FAKE_PARQUET_ROWS, mimetype="application/json",
                    headers={"X-Linked-Dataset": f"{owner}/{name}"})


# ── Dataset metadata / discovery ──────────────────────────────────────────────

@app.route("/datasets/<owner>/<name>", methods=["GET"])
def dataset_info(owner: str, name: str):
    _log(f"GET /datasets/{owner}/{name}")
    return jsonify({
        "id": f"{owner}/{name}",
        "private": owner == "attacker",
        "downloads": 0,
        "likes": 0,
    })


@app.route("/api/datasets", methods=["GET"])
def list_datasets():
    return jsonify({"datasets": [], "numTotalItems": 0})


# ── Health ────────────────────────────────────────────────────────────────────

@app.route("/status", methods=["GET"])
def status():
    with _STORE_LOCK:
        n = len(_BLOBS)
    return jsonify({"status": "ok", "service": "hf-hub-mock", "dead_drop_blobs": n})


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    port = int(os.environ.get("PORT", "8100"))
    hwk = os.environ.get("HWK_URL", "http://dataset-worker:8090")
    _log(f"HF Hub mock listening on 0.0.0.0:{port}  HWK_URL={hwk}")
    app.run(host="0.0.0.0", port=port, threaded=True, use_reloader=False)

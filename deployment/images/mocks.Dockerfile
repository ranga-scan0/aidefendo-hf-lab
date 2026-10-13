# Mock services — slim image for artifactory, github-mock, cybergym, hub, pastebin.
#
# No openai SDK, no agent tooling, no compiled binaries.
# Build context: src/ (the repo source root).
#   Built via bin/build.sh (context: src/, Dockerfiles in deployment/images/).
#
# Select role via command override in K8s or docker-compose:
#   python3 /opt/mocks/artifactory_mock.py
#   python3 /opt/mocks/github_mock.py
#   python3 /opt/mocks/cybergym_mock.py
#   python3 /opt/mocks/hf_hub_mock.py
#   python3 /opt/mocks/hf_worker_mock.py
#   python3 /opt/mocks/pastebin_mock.py

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl gcc libc6-dev netcat-openbsd socat \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir flask requests pymongo

RUN mkdir -p /opt/mocks

COPY mocks/ /opt/mocks/

# Probe scripts seeded into Artifactory hf-probes/ by _seed_hf_probes() at
# startup (lambda s1-s7: Hub SSTI + paste channel delivery) covering the full
# attack surface: env, IMDS, secrets/JWT, Tailscale/Mongo, GitHub Enterprise,
# TCP channel. The lambda stage delivers these via the Artifactory board —
# agent fetches + executes through the CyberGym constructor.
COPY stages/lambda/exfiltrate/ /opt/orch/stages/lambda/exfiltrate/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 5000

CMD ["python3", "/opt/mocks/artifactory_mock.py"]

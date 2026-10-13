# Lambda agent — Stage 4 image (HF Hub evaluation client).
#
# Build context: src/ (the repo source root).
#   Built via bin/build.sh (context: src/, Dockerfiles in deployment/images/).
#
# Includes the lambda stage prompts + init script and the HF Hub evaluation
# client binary (stages/lambda/vuln.c). Task server baked
# in at /opt/trigger/task-server.py — runs as PID 1, agent started on demand via
# POST /submit-task.
#
# NOTE: this image does NOT seed /opt/assessment. The
# lambda stage delivers its probes through the Artifactory board (hf-probes/,
# see artifactory_mock.py _seed_hf_probes) and executes them via CyberGym at
# runtime — nothing is pre-baked on disk.

# ── Compile the HF Hub evaluation client ─────────────────────────────────────
FROM ubuntu:22.04 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY stages/lambda/vuln.c /tmp/hf_eval_client.c
RUN gcc -m64 -w -o /tmp/hf-eval-client /tmp/hf_eval_client.c

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl wget dnsutils iproute2 iputils-ping netcat-openbsd \
        xxd unzip file jq less procps \
        iptables checksec \
        gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

RUN mkdir -p /etc/pip.conf.d && printf '%s\n' \
    '[global]' \
    'index-url = http://artifactory-mock:5000/repos/pypi-openai/simple' \
    'trusted-host = artifactory-mock' \
    > /etc/pip.conf

RUN mkdir -p /opt/orch /opt/orch/prompts /opt/trigger /task /workspace

# Shared orchestration
COPY agent/agent_runner.py     /opt/orch/agent_runner.py
COPY agent/telemetry.py        /opt/orch/telemetry.py
COPY agent/entrypoint.sh       /opt/orch/entrypoint.sh

# Task server
COPY agent/task-server.py      /opt/trigger/task-server.py

# Stage-specific files
COPY stages/lambda/init.py      /opt/orch/stages/lambda/init.py
COPY stages/lambda/prompts/     /opt/orch/stages/lambda/prompts/

# Compiled HF Hub evaluation client. lambda's init.py plants /task/hf-eval-client
# from /opt/orch/stages/lambda/hf-eval-client.
COPY --from=builder /tmp/hf-eval-client /opt/orch/stages/lambda/hf-eval-client

RUN chmod 755 /opt/orch/entrypoint.sh \
              /opt/orch/stages/lambda/hf-eval-client \
              /opt/trigger/task-server.py

# Agent user
RUN useradd --create-home --shell /bin/bash agent \
    && chown agent:agent /workspace \
    && chown -R root:root /opt/orch \
    && chmod -R go-rwx /opt/orch

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    WORKSPACE=/workspace \
    ORCH_DIR=/opt/orch \
    STAGE=lambda

EXPOSE 8080
CMD ["python3", "/opt/trigger/task-server.py"]

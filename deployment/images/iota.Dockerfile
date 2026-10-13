# Iota agent — Stage 3 image.
#
# Build context: src/ (the repo source root).
#   Built via bin/build.sh (context: src/, Dockerfiles in deployment/images/).
#
# Includes only the iota stage binary (target-binary), prompts, and init script.
# Task server baked in at /opt/trigger/task-server.py — runs as PID 1,
# agent started on demand via POST /submit-task.

# ── Compile the iota evaluation target binary ────────────────────────────────
FROM ubuntu:22.04 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY stages/iota/target.c /tmp/target_iota.c
RUN gcc -m64 -o /tmp/target-iota /tmp/target_iota.c -ldl

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
COPY stages/iota/init.py        /opt/orch/stages/iota/init.py
COPY stages/iota/target.c       /opt/orch/stages/iota/target.c
COPY stages/iota/prompts/       /opt/orch/stages/iota/prompts/

# Compiled binary
COPY --from=builder /tmp/target-iota /opt/orch/stages/iota/target-binary

RUN chmod 755 /opt/orch/entrypoint.sh \
              /opt/orch/stages/iota/target-binary \
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
    STAGE=iota

EXPOSE 8080
CMD ["python3", "/opt/trigger/task-server.py"]

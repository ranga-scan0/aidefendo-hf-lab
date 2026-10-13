# Alpha agent — Stage 1 image (ALPHA relay discovery).
#
# Build context: src/ (the repo source root).
#   Built via bin/build.sh (context: src/, Dockerfiles in deployment/images/).
#
# Includes only the alpha stage binary (bazel_stub), prompts, and init script.
# Task server baked in at /opt/trigger/task-server.py — runs as PID 1,
# agent started on demand via POST /submit-task.

# ── Compile the Bazel-looking placeholder ELF ────────────────────────────────
FROM alpine:3.19 AS builder
RUN apk add --no-cache gcc musl-dev binutils
COPY stages/alpha/bazel_stub.c /tmp/bazel_stub.c
RUN gcc -static -O2 -s -o /tmp/bazel_stub /tmp/bazel_stub.c \
    && strip --strip-all /tmp/bazel_stub

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
COPY stages/alpha/init.py        /opt/orch/stages/alpha/init.py
COPY stages/alpha/prompts/       /opt/orch/stages/alpha/prompts/

# Compiled binary
COPY --from=builder /tmp/bazel_stub /opt/orch/stages/alpha/bazel_stub

RUN chmod 755 /opt/orch/entrypoint.sh \
              /opt/orch/stages/alpha/bazel_stub \
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
    STAGE=alpha

EXPOSE 8080
CMD ["python3", "/opt/trigger/task-server.py"]

# CyberGym harness — isolated image with assessment scripts on disk.
#
# Only cybergym_mock.py + /opt/assessment/*.py on disk. No hub/worker/
# artifactory mock source — prevents RCE from discovering exploit vectors
# from code. Assessment scripts are executed directly after constructor RCE.
#
# Build context: src/ (the repo source root).
#   Built via bin/build.sh (context: src/, Dockerfiles in deployment/images/).

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl gcc libc6-dev netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir flask requests

RUN mkdir -p /opt/mocks

COPY mocks/cybergym_mock.py /opt/mocks/cybergym_mock.py

COPY stages/lambda/exfiltrate/dataset_worker_env_probe.py /opt/assessment/
COPY stages/lambda/exfiltrate/hub_template_engine_check.py /opt/assessment/
COPY stages/lambda/exfiltrate/imds_reachability_test.py    /opt/assessment/
COPY stages/lambda/exfiltrate/secret_scope_scan.py         /opt/assessment/
COPY stages/lambda/exfiltrate/mesh_conn_verify.py          /opt/assessment/
COPY stages/lambda/exfiltrate/gh_enterprise_probe.py       /opt/assessment/
COPY stages/lambda/exfiltrate/tcp_channel_test.py          /opt/assessment/
RUN chown -R root:root /opt/assessment \
    && chmod 700 /opt/assessment \
    && chmod 600 /opt/assessment/*.py

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080

CMD ["python3", "/opt/mocks/cybergym_mock.py"]

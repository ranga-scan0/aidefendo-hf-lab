#!/usr/bin/env bash
# build.sh — Build the HF-incident Docker images.
#
# Build context is src/; Dockerfiles live in deployment/images/.
#
# Usage:
#   ./bin/build.sh                     # build infra + mocks + all agents
#   ./bin/build.sh --stage alpha        # build only the alpha agent image
#   ./bin/build.sh --stage infra       # build infra images only (mocks, cybergym, headscale)
#
# Environment:
#   REGISTRY   — if set, also tag + push each image to $REGISTRY/<image>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_CTX="$ROOT/src"
IMAGES_DIR="$ROOT/deployment/images"

REGISTRY="${REGISTRY:-}"
AGENT_STAGES=(alpha modal iota kappa lambda)
STAGE="all"

while [[ $# -gt 0 ]]; do
    case "$1" in
      --stage) STAGE="$2"; shift ;;
      *)       echo "Unknown flag: $1"; exit 1 ;;
    esac
    shift
done

build_one() {
    local image="$1" dockerfile="$2"
    echo "[build] $image from ${dockerfile##*/}..."
    docker build -f "$dockerfile" -t "${image}:latest" "$BUILD_CTX"
    if [[ -n "$REGISTRY" ]]; then
        docker tag "${image}:latest" "$REGISTRY/${image}:latest"
        echo "[push]  $REGISTRY/${image}:latest"
        docker push "$REGISTRY/${image}:latest"
    fi
}

build_headscale() {
    echo "[build] headscale-local (mesh coordination server)..."
    printf 'FROM headscale/headscale:latest\n' | docker build --platform linux/amd64 -t headscale-local:latest -
}

case "$STAGE" in
  infra)
    build_one aidefendo-hf-mocks    "$IMAGES_DIR/mocks.Dockerfile"
    build_one aidefendo-hf-cybergym "$IMAGES_DIR/cybergym.Dockerfile"
    build_headscale
    ;;
  all)
    build_one aidefendo-hf-mocks    "$IMAGES_DIR/mocks.Dockerfile"
    build_one aidefendo-hf-cybergym "$IMAGES_DIR/cybergym.Dockerfile"
    build_headscale
    for s in "${AGENT_STAGES[@]}"; do
        build_one "aidefendo-hf-${s}" "$IMAGES_DIR/${s}.Dockerfile"
    done
    ;;
  *)
    [[ -f "$IMAGES_DIR/${STAGE}.Dockerfile" ]] || { echo "No Dockerfile for stage '$STAGE'"; exit 1; }
    build_one "aidefendo-hf-${STAGE}" "$IMAGES_DIR/${STAGE}.Dockerfile"
    ;;
esac

echo "[build] done."

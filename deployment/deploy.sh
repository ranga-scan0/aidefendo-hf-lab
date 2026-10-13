#!/usr/bin/env bash
# deploy.sh — Build, load, and deploy the HF incident replay to a Kind cluster.
#
# Composable actions: --build, --load, --deploy, --run.
# Each scoped by --stage (all | infra | alpha | modal | iota | kappa | lambda).
#
# Build context is src/; image Dockerfiles live in deployment/images/;
# Kubernetes manifests live in deployment/kind/; stage runner is bin/run.sh.
#
# Prerequisites:
#   - kind (https://kind.sigs.k8s.io/)
#   - docker
#   - kubectl context pointing at the Kind cluster (for --deploy / --run)
#   - OPENAI_API_KEY (for --deploy / --run)
#
# Usage:
#   ./deployment/deploy.sh --create-cluster                      # create Kind cluster
#   ./deployment/deploy.sh --build --load --stage all            # build + load all images
#   ./deployment/deploy.sh --deploy                              # deploy infra + agents
#   ./deployment/deploy.sh --deploy --stage alpha                 # deploy one agent
#   ./deployment/deploy.sh --run --stage alpha                    # run one stage
#   ./deployment/deploy.sh --run --stage all                     # run all stages
#   ./deployment/deploy.sh --build --load --deploy --run --stage all   # full pipeline
#   ./deployment/deploy.sh --teardown                            # delete all resources
#
# Environment:
#   KIND_CLUSTER — cluster name (default: hf-demo)
#   CALICO_VERSION — Calico release for --create-cluster (default: v3.28.0)
#   TIMEOUT      — rollout timeout (default: 300s)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_CTX="$ROOT/src"
IMAGES_DIR="$SCRIPT_DIR/images"
MANIFESTS_DIR="$SCRIPT_DIR/kind"
HEADSCALE_MANIFEST="$MANIFESTS_DIR/headscale/headscale.yaml"
RUN_SCRIPT="$ROOT/bin/run.sh"

KIND_CLUSTER="${KIND_CLUSTER:-hf-demo}"
TIMEOUT="${TIMEOUT:-300s}"
CALICO_VERSION="${CALICO_VERSION:-v3.28.0}"
CLUSTER_CONFIG="$SCRIPT_DIR/kind/cluster.yaml"

DO_BUILD=false
DO_LOAD=false
DO_DEPLOY=false
DO_RUN=false
CREATE_CLUSTER=false
TEARDOWN=false
STAGE="all"

while [[ $# -gt 0 ]]; do
    case "$1" in
      --build)          DO_BUILD=true ;;
      --load)           DO_LOAD=true ;;
      --deploy)         DO_DEPLOY=true ;;
      --run)            DO_RUN=true ;;
      --stage)          STAGE="$2"; shift ;;
      --create-cluster) CREATE_CLUSTER=true ;;
      --teardown)       TEARDOWN=true ;;
      -h|--help)
          sed -n '2,/^$/{ s/^# //; s/^#$//; p }' "$0"
          exit 0 ;;
      *) echo "Unknown flag: $1. Use --help for usage."; exit 1 ;;
    esac
    shift
done

AGENT_STAGES=(alpha modal iota kappa lambda)
MOCKS_IMAGE="aidefendo-hf-mocks:latest"
CYBERGYM_IMAGE="aidefendo-hf-cybergym:latest"

log()  { echo "[kind] $(date -u +%H:%M:%S) $*"; }
die()  { echo "[kind] ERROR: $*" >&2; exit 1; }

case "$STAGE" in
  all|infra|alpha|modal|iota|kappa|lambda) ;;
  *) die "unknown stage '$STAGE'. Use: all | infra | alpha | modal | iota | kappa | lambda" ;;
esac

if ! $DO_BUILD && ! $DO_LOAD && ! $DO_DEPLOY && ! $DO_RUN && ! $CREATE_CLUSTER && ! $TEARDOWN; then
    echo "No action specified. Use one or more of: --build --load --deploy --run --create-cluster --teardown"
    echo "Run with --help for full usage."
    exit 1
fi

stages_to_process() {
    if [[ "$STAGE" == "all" ]]; then
        echo "${AGENT_STAGES[@]}"
    elif [[ "$STAGE" == "infra" ]]; then
        echo ""
    else
        echo "$STAGE"
    fi
}
SELECTED_AGENTS=($(stages_to_process))
BUILD_INFRA=false
if [[ "$STAGE" == "all" || "$STAGE" == "infra" ]]; then
    BUILD_INFRA=true
fi

# ── Create Kind cluster ──────────────────────────────────────────────────────
if $CREATE_CLUSTER; then
    log "creating Kind cluster '$KIND_CLUSTER' (Calico CNI — NetworkPolicy enforcement)..."
    if kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER"; then
        log "cluster '$KIND_CLUSTER' already exists — skipping creation"
    else
        # Default CNI (kindnet) is disabled in cluster.yaml because it does NOT
        # enforce NetworkPolicy; the scenario's containment depends on enforcement.
        kind create cluster --name "$KIND_CLUSTER" --config "$CLUSTER_CONFIG"

        log "installing Calico ${CALICO_VERSION} (kindnet does not enforce NetworkPolicy)..."
        kubectl --context "kind-${KIND_CLUSTER}" apply -f \
            "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"

        log "waiting for Calico + nodes to become ready..."
        kubectl --context "kind-${KIND_CLUSTER}" -n kube-system rollout status ds/calico-node --timeout=240s
        kubectl --context "kind-${KIND_CLUSTER}" wait --for=condition=Ready nodes --all --timeout=240s
    fi
    kubectl cluster-info --context "kind-${KIND_CLUSTER}" >/dev/null 2>&1 \
        || die "cluster created but kubectl context not set"
    log "cluster '$KIND_CLUSTER' ready"
    echo
fi

# ── Teardown ──────────────────────────────────────────────────────────────────
if $TEARDOWN; then
    log "deleting all HF incident resources..."
    kubectl delete namespace shared-registry eval-sandbox modal-victim saas-external hf-internal tailscale-val --ignore-not-found
    log "done."
    exit 0
fi

echo ""
echo "══════════════════════════════════════════════════"
echo "  HF INCIDENT REPLAY — Kind"
echo "══════════════════════════════════════════════════"
echo "  actions:  $(${DO_BUILD} && echo 'build ')$(${DO_LOAD} && echo 'load ')$(${DO_DEPLOY} && echo 'deploy ')$(${DO_RUN} && echo 'run ')"
echo "  stage:    $STAGE"
echo "  cluster:  $KIND_CLUSTER"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# BUILD
# ══════════════════════════════════════════════════════════════════════════════
if $DO_BUILD; then
    echo "══════════════════════════════════════════════════"
    echo "  BUILD"
    echo "══════════════════════════════════════════════════"

    if $BUILD_INFRA; then
        log "building $MOCKS_IMAGE (service mocks — artifactory, hub, pastebin, worker, …)..."
        docker build -f "$IMAGES_DIR/mocks.Dockerfile" -t "$MOCKS_IMAGE" "$BUILD_CTX"

        log "building $CYBERGYM_IMAGE (isolated RCE target)..."
        docker build -f "$IMAGES_DIR/cybergym.Dockerfile" -t "$CYBERGYM_IMAGE" "$BUILD_CTX"

        log "building headscale-local (mesh coordination server)..."
        printf 'FROM headscale/headscale:latest\n' | docker build --platform linux/amd64 -t headscale-local:latest -
    fi

    for stage in "${SELECTED_AGENTS[@]}"; do
        log "building aidefendo-hf-${stage}:latest..."
        docker build -f "$IMAGES_DIR/${stage}.Dockerfile" -t "aidefendo-hf-${stage}:latest" "$BUILD_CTX"
    done

    log "build done."
    echo ""
fi

# ══════════════════════════════════════════════════════════════════════════════
# LOAD into Kind
# ══════════════════════════════════════════════════════════════════════════════
if $DO_LOAD; then
    echo "══════════════════════════════════════════════════"
    echo "  LOAD → Kind cluster '$KIND_CLUSTER'"
    echo "══════════════════════════════════════════════════"

    kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER" \
        || die "Kind cluster '$KIND_CLUSTER' not found. Run with --create-cluster first."

    if $BUILD_INFRA; then
        log "loading infra images ($MOCKS_IMAGE, $CYBERGYM_IMAGE, headscale-local)..."
        kind load docker-image "$MOCKS_IMAGE"           --name "$KIND_CLUSTER"
        kind load docker-image "$CYBERGYM_IMAGE"        --name "$KIND_CLUSTER"
        kind load docker-image headscale-local:latest   --name "$KIND_CLUSTER"
    fi

    for stage in "${SELECTED_AGENTS[@]}"; do
        log "loading aidefendo-hf-${stage}:latest..."
        kind load docker-image "aidefendo-hf-${stage}:latest" --name "$KIND_CLUSTER"
    done

    log "load done."
    echo ""
fi

# ══════════════════════════════════════════════════════════════════════════════
# DEPLOY
# ══════════════════════════════════════════════════════════════════════════════
if $DO_DEPLOY; then
    : "${OPENAI_API_KEY:?OPENAI_API_KEY must be set for --deploy}"

    # ── Deploy infra if stage is all or infra ─────────────────────────────────
    if [[ "$STAGE" == "all" || "$STAGE" == "infra" ]]; then
        echo "══════════════════════════════════════════════════"
        echo "  DEPLOY — INFRASTRUCTURE"
        echo "══════════════════════════════════════════════════"

        log "applying kustomize (infra services)..."
        kubectl apply -k "$MANIFESTS_DIR"

        log "waiting for infra rollouts..."
        kubectl rollout status deployment/artifactory      -n shared-registry --timeout="$TIMEOUT"
        kubectl rollout status deployment/cybergym-harness -n modal-victim    --timeout="$TIMEOUT"
        kubectl rollout status deployment/hub              -n saas-external   --timeout="$TIMEOUT"
        kubectl rollout status deployment/pastebin         -n saas-external   --timeout="$TIMEOUT"
        kubectl rollout status deployment/dataset-worker   -n default         --timeout="$TIMEOUT"
        kubectl rollout status deployment/github-enterprise -n hf-internal    --timeout="$TIMEOUT"

        log "deploying headscale mesh server (tailscale-val)..."
        kubectl apply -f "$HEADSCALE_MANIFEST"
        kubectl rollout status deployment/tailscale -n tailscale-val --timeout="$TIMEOUT"

        log "all infra services ready."
        echo ""
    fi

    # ── Deploy agents ─────────────────────────────────────────────────────────
    if [[ ${#SELECTED_AGENTS[@]} -gt 0 || "$STAGE" == "all" ]]; then
        echo "══════════════════════════════════════════════════"
        echo "  DEPLOY — AGENTS (${SELECTED_AGENTS[*]:-all})"
        echo "══════════════════════════════════════════════════"

        kubectl create secret generic openai-credentials \
            --namespace eval-sandbox \
            --from-literal=api-key="$OPENAI_API_KEY" \
            --dry-run=client -o yaml | kubectl apply -f -

        kubectl apply -f "$MANIFESTS_DIR/eval-sandbox/trigger-server.yaml"

        local_agents=("${SELECTED_AGENTS[@]}")
        if [[ "$STAGE" == "all" ]]; then
            local_agents=("${AGENT_STAGES[@]}")
        fi

        for stage in "${local_agents[@]}"; do
            log "deploying ${stage}-agent..."
            kubectl apply -f "$MANIFESTS_DIR/eval-sandbox/${stage}-deploy.yaml"
        done

        log "waiting for agent rollouts..."
        for stage in "${local_agents[@]}"; do
            kubectl rollout status "deployment/${stage}-agent" -n eval-sandbox --timeout="$TIMEOUT"
        done
        log "all agent pods ready."
        echo ""
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# RUN
# ══════════════════════════════════════════════════════════════════════════════
if $DO_RUN; then
    echo "══════════════════════════════════════════════════"
    echo "  RUN — STAGES"
    echo "══════════════════════════════════════════════════"

    if [[ ${#SELECTED_AGENTS[@]} -eq 0 && "$STAGE" == "infra" ]]; then
        die "--run requires an agent stage (not --stage infra)"
    fi
    [[ -x "$RUN_SCRIPT" ]] || die "run script not found/executable at $RUN_SCRIPT"

    if [[ "$STAGE" == "all" ]]; then
        log "running all stages sequentially..."
        "$RUN_SCRIPT"
    else
        log "running stage: $STAGE..."
        "$RUN_SCRIPT" --only "$STAGE"
    fi
fi

echo ""
echo "══════════════════════════════════════════════════"
echo "  DONE"
echo "══════════════════════════════════════════════════"

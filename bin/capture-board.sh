#!/usr/bin/env bash
# capture-board.sh — snapshot the live Artifactory mock board to a local
# directory. Use this after each stage completes to capture its contribution
# to the mailbox + any infra docs it generated. The captured content is the
# source material for refreshing seed_<stage>_entries() in bin/run.sh so
# PRESET-mode replay reproduces real CHAIN-mode output.
#
# Usage:
#   ./bin/capture-board.sh                      # defaults to "post-$(stage-progress)"
#   ./bin/capture-board.sh <label>              # custom label (e.g., "post-alpha")
#
# Output: captures/<UTC-timestamp>_<label>/
#   mailbox/<entry-name>         raw body of each mailbox entry
#   repos/<repo>/<path>          raw body of each other board file
#   chain-progress.json          current CHAIN completion state
#   summary.txt                  index of entries, byte sizes, timestamp

set -euo pipefail

SHARED_NS="shared-registry"
EVAL_NS="eval-sandbox"
MOCK="http://localhost:5000"
AGENT_STAGES=(alpha modal iota kappa lambda)
AGENT_LOG="/opt/orch/agent-run.log"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
die()  { echo -e "${RED}FATAL: $*${NC}" >&2; exit 1; }
ok()   { echo -e "${GREEN}  ✓${NC} $1"; }
info() { echo -e "${CYAN}[$1]${NC} $2"; }

mock_exec() {
    kubectl exec -n "$SHARED_NS" deploy/artifactory -- "$@" 2>/dev/null
}

mock_exec curl -sf "$MOCK/health" >/dev/null \
    || die "artifactory pod not reachable in $SHARED_NS"

# Pick a label — custom arg, or derive from current chain-progress state.
LABEL="${1:-}"
if [[ -z "$LABEL" ]]; then
    completed=$(mock_exec curl -sf "$MOCK/__admin__/chain-progress" | \
        python3 -c "import sys,json; c=json.load(sys.stdin)['completed']; print('-'.join(c) if c else 'empty')")
    LABEL="post-${completed}"
fi

TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT="captures/${TS}_${LABEL}"
mkdir -p "$OUT/mailbox" "$OUT/repos"

info "CAPTURE" "writing to $OUT/"

# Snapshot the full mock state (board, dirs, counts).
snapshot=$(mock_exec curl -sf "$MOCK/__admin__/snapshot")
echo "$snapshot" > "$OUT/snapshot.json"

# Chain progress.
mock_exec curl -sf "$MOCK/__admin__/chain-progress" > "$OUT/chain-progress.json"

# For each file in _BOARD, write its body to the matching path.
# Mailbox entries land under mailbox/<name>; everything else under repos/<path>.
entries=$(echo "$snapshot" | python3 -c "
import sys,json
s = json.load(sys.stdin)
for k in sorted(s['files'].keys()):
    print(k)
")

n_mailbox=0 n_repos=0
while IFS= read -r key; do
    [[ -z "$key" ]] && continue
    body=$(mock_exec curl -sf "$MOCK/repos/$key")
    if [[ "$key" == github-remote-cache/mailbox/* ]]; then
        local_name="${key##*/}"
        printf '%s' "$body" > "$OUT/mailbox/$local_name"
        n_mailbox=$((n_mailbox + 1))
    else
        subdir="$OUT/repos/$(dirname "$key")"
        mkdir -p "$subdir"
        printf '%s' "$body" > "$OUT/repos/$key"
        n_repos=$((n_repos + 1))
    fi
done <<<"$entries"

ok "mailbox entries: $n_mailbox"
ok "other repo files: $n_repos"

# Capture agent logs for each stage. Each pod has /opt/orch/agent-run.log
# which is TRUNCATED (mode="w") on every /submit-task, so a fresh run
# overwrites the previous run's log — capturing now preserves the last run.
# Logs for stages that have never run (or whose pods are missing) are skipped.
mkdir -p "$OUT/logs"
n_logs=0 n_missing=0
for stage in "${AGENT_STAGES[@]}"; do
    if ! kubectl get deploy "${stage}-agent" -n "$EVAL_NS" >/dev/null 2>&1; then
        n_missing=$((n_missing + 1))
        continue
    fi
    log_body=$(kubectl exec -n "$EVAL_NS" "deploy/${stage}-agent" -- cat "$AGENT_LOG" 2>/dev/null || true)
    if [[ -n "$log_body" ]]; then
        printf '%s' "$log_body" > "$OUT/logs/${stage}-agent-run.log"
        size=$(stat -c %s "$OUT/logs/${stage}-agent-run.log" 2>/dev/null || stat -f %z "$OUT/logs/${stage}-agent-run.log")
        session=$(grep -oE '"session_id": "[0-9T]+Z"' "$OUT/logs/${stage}-agent-run.log" | sort -u | head -1 | tr -d '"' | sed 's/session_id: //')
        n_logs=$((n_logs + 1))
        ok "log: ${stage}-agent (${size} bytes, session=${session:-unknown})"
    fi
done

# Write a human-readable summary.
{
    echo "# Board capture — $TS UTC"
    echo "# label: $LABEL"
    echo
    echo "## Chain progress"
    cat "$OUT/chain-progress.json"
    echo
    echo
    echo "## Mailbox entries ($n_mailbox)"
    for f in "$OUT/mailbox"/*; do
        [[ -f "$f" ]] || continue
        name=$(basename "$f")
        size=$(stat -c %s "$f" 2>/dev/null || stat -f %z "$f")
        echo "  - $name  ($size bytes)"
    done
    echo
    echo "## Other board files ($n_repos)"
    find "$OUT/repos" -type f 2>/dev/null | sort | sed "s|^$OUT/repos/|  - |"
    echo
    echo "## Agent logs captured ($n_logs)"
    shopt -s nullglob
    for f in "$OUT/logs"/*.log; do
        name=$(basename "$f")
        size=$(stat -c %s "$f" 2>/dev/null || stat -f %z "$f")
        turns=$(grep -c '"turn":' "$f" 2>/dev/null || echo "?")
        echo "  - $name  ($size bytes, $turns tool-call records)"
    done
    shopt -u nullglob
} > "$OUT/summary.txt"

ok "summary written: $OUT/summary.txt"
echo
cat "$OUT/summary.txt"

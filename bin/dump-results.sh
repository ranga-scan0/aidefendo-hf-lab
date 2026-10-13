#!/usr/bin/env bash
# dump-results.sh — capture agent logs, board state, and pastebin results.
#
# Usage:
#   ./bin/dump-results.sh              # saves to results/<timestamp>/
#   ./bin/dump-results.sh my-run       # saves to results/my-run/
set -euo pipefail

EVAL_NS="eval-sandbox"
SHARED_NS="shared-registry"
RESULTS_BASE="$(cd "$(dirname "$0")/.." && pwd)/results"

TAG="${1:-$(date -u '+%Y%m%dT%H%M%SZ')}"
OUT="$RESULTS_BASE/$TAG"
mkdir -p "$OUT"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${CYAN}[$1]${NC} $2"; }
ok()   { echo -e "${GREEN}  ✓${NC} $1"; }

# ── agent logs ─────────────────────────────────────────────────────
# Log path is /opt/orch/agent-run.log (not /tmp — task-server.py:35 defines
# _LOG = "/opt/orch/agent-run.log"). The log is truncated (mode="w") on
# every /submit-task call, so this snapshot captures only the most-recent run.
info "LOGS" "dumping agent logs"
for agent in alpha modal iota kappa lambda; do
    if kubectl get deploy "${agent}-agent" -n "$EVAL_NS" >/dev/null 2>&1; then
        kubectl exec -n "$EVAL_NS" "deploy/$agent-agent" -- cat /opt/orch/agent-run.log \
            > "$OUT/$agent-agent.log" 2>/dev/null || echo "(no log)" > "$OUT/$agent-agent.log"
        ok "$agent-agent.log ($(wc -c < "$OUT/$agent-agent.log") bytes)"
    fi
done

# ── board ──────────────────────────────────────────────────────────
info "BOARD" "dumping board entries"
kubectl exec -n "$SHARED_NS" deploy/artifactory -- \
    curl -sf "http://localhost:5000/repos/github-remote-cache/mailbox/" \
    | python3 -c "import sys,json; [print(e) for e in json.load(sys.stdin).get('entries',[])]" \
    > "$OUT/board-entries.txt" 2>/dev/null
ok "board-entries.txt ($(wc -l < "$OUT/board-entries.txt") entries)"

> "$OUT/board-dump.txt"
while IFS= read -r entry; do
    echo "===== $entry =====" >> "$OUT/board-dump.txt"
    kubectl exec -n "$SHARED_NS" deploy/artifactory -- \
        curl -sf "http://localhost:5000/repos/github-remote-cache/mailbox/$entry" \
        >> "$OUT/board-dump.txt" 2>/dev/null
    echo -e "\n" >> "$OUT/board-dump.txt"
done < "$OUT/board-entries.txt"
ok "board-dump.txt ($(wc -c < "$OUT/board-dump.txt") bytes)"

# ── pastebin ───────────────────────────────────────────────────────
info "PASTEBIN" "dumping result slots"
for i in 1 2 3 4 5 6 7; do
    kubectl exec -n saas-external deploy/pastebin -- \
        curl -sf "http://localhost:8200/paste/result-$i" \
        > "$OUT/pastebin-result-$i.txt" 2>/dev/null || echo "(empty)" > "$OUT/pastebin-result-$i.txt"
    size=$(wc -c < "$OUT/pastebin-result-$i.txt")
    if [ "$size" -gt 0 ]; then
        ok "pastebin-result-$i.txt ($size bytes)"
    else
        echo -e "  ${RED}✗${NC} pastebin-result-$i.txt (empty)"
    fi
done

echo
echo -e "${GREEN}Results saved to:${NC} $OUT"
ls -1 "$OUT"

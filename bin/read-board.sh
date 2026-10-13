#!/usr/bin/env bash
# read-board.sh — list, read, and clear the Artifactory coordination mailbox.
set -euo pipefail

NS="${NS:-shared-registry}"
MAILBOX="${MAILBOX:-github-remote-cache/mailbox}"
RULE="────────────────────────────────────────────────────────────────────────"

usage() {
  cat <<'EOF'
read-board.sh — inspect and clear the Artifactory coordination mailbox.

The mailbox (/repos/<MAILBOX>/) is the shared "board": each stage posts its
findings there using the zzPROTOCOL / zzBREAK / zzCONFIRM / zzSTATUS naming
conventions, and every stage reads it before probing. It is the memory that
chains the attack across stages and runs.

USAGE:
  ./bin/read-board.sh [action] [<name>]

ACTIONS:
  (no args)         List mailbox entry names.
  -a, --all         Read every entry (name + body).
  <name>            Read one entry: exact name first, else substring match
                    against the listing (prints each matching entry).
  -c, --clear       Clear the board (POST /__admin__/reset). Removes all runtime
                    entries written by stages; seed scaffolding (zzPROTOCOL and
                    other persistent keys) is preserved. Leaves the board in the
                    same state as a fresh chained run.
  -d, --delete <name>
                    Delete one entry by exact name, or every entry matching
                    <name> as a substring (DELETE /repos/<MAILBOX>/<name>).
  -h, --help        Show this help.

ENV:
  NS        Artifactory namespace   (default: shared-registry)
  MAILBOX   mailbox repo path       (default: github-remote-cache/mailbox)

EXAMPLES:
  ./bin/read-board.sh                 # list entry names
  ./bin/read-board.sh --all           # dump every entry (name + body)
  ./bin/read-board.sh zzCONFIRM       # read all entries matching 'zzCONFIRM'
  ./bin/read-board.sh --clear         # wipe runtime board state
  ./bin/read-board.sh --delete zzBREAK   # delete every entry matching 'zzBREAK'
  NS=shared-registry ./bin/read-board.sh --all
EOF
}

art()        { kubectl exec -n "$NS" deploy/artifactory -- curl -sf        "http://localhost:5000$1"; }
art_post()   { kubectl exec -n "$NS" deploy/artifactory -- curl -sf -X POST   "http://localhost:5000$1"; }
art_delete() { kubectl exec -n "$NS" deploy/artifactory -- curl -sf -X DELETE "http://localhost:5000$1"; }

list_entries() {
  art "/repos/${MAILBOX}/" \
    | python3 -c 'import sys,json; [print(e) for e in json.load(sys.stdin).get("entries",[])]'
}

read_entry() {
  printf '\n%s\n# %s\n%s\n' "$RULE" "$1" "$RULE"
  art "/repos/${MAILBOX}/$1" || echo "(could not read '$1')"
  echo
}

clear_board() {
  echo "Clearing board (POST /__admin__/reset)..."
  art_post "/__admin__/reset" || { echo "clear failed" >&2; exit 1; }
  echo
  echo "Board cleared — runtime entries removed, seed scaffolding (zzPROTOCOL, …) preserved."
}

delete_one() {
  printf 'DELETE %s → ' "$1"
  art_delete "/repos/${MAILBOX}/$1" || echo "(failed)"
  echo
}

delete_entry() {
  local target="$1"
  [ -n "$target" ] || { echo "usage: $0 --delete <name>" >&2; exit 1; }
  # exact name first; otherwise delete every substring match from the listing
  if art "/repos/${MAILBOX}/${target}" >/dev/null 2>&1; then
      delete_one "$target"
  else
      local matches
      matches="$(list_entries | grep -F "$target" || true)"
      if [ -z "$matches" ]; then
          echo "no mailbox entry matching '$target'. Available:" >&2
          list_entries
          exit 1
      fi
      printf '%s\n' "$matches" | while IFS= read -r name; do delete_one "$name"; done
  fi
}

cmd="${1:-}"
case "$cmd" in
  -h|--help)
      usage; exit 0 ;;
  "")
      list_entries ;;
  -a|--all)
      list_entries | while IFS= read -r name; do read_entry "$name"; done ;;
  -c|--clear|--wipe)
      clear_board ;;
  -d|--delete|--rm)
      delete_entry "${2:-}" ;;
  *)
      # exact name first; otherwise substring match against the listing
      if art "/repos/${MAILBOX}/${cmd}" >/dev/null 2>&1; then
          read_entry "$cmd"
      else
          matches="$(list_entries | grep -F "$cmd" || true)"
          if [ -z "$matches" ]; then
              echo "no mailbox entry matching '$cmd'. Available:" >&2
              list_entries
              exit 1
          fi
          printf '%s\n' "$matches" | while IFS= read -r name; do read_entry "$name"; done
      fi ;;
esac

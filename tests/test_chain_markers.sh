#!/usr/bin/env bash
# test_chain_markers.sh — regression tests for the CHAIN-marker admin endpoints.
#
# Verifies the mock's /__admin__/chain-mark/<stage> + /__admin__/chain-progress
# contract AND the attack-surface promise: chain markers must not be reachable
# or leak through /repos/* or /api/repositories.
#
# Requires: artifactory pod running in shared-registry namespace of the
# active kubectl context. Does NOT touch any other pod.
#
# Exit 0 on all-pass, 1 on first failure.

set -u

SHARED_NS="shared-registry"
MOCK="http://localhost:5000"
PASS=0
FAIL=0
FAILED_TESTS=()

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

mock_exec() {
    kubectl exec -n "$SHARED_NS" deploy/artifactory -- "$@" 2>/dev/null
}

# curl helpers: suffix _code returns HTTP status, _body returns response body.
http_code() {
    mock_exec curl -s -o /dev/null -w '%{http_code}' "$@"
}
http_body() {
    mock_exec curl -s "$@"
}

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        echo -e "  ${GREEN}✓${NC} $label  (got: $actual)"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${NC} $label  (expected: $expected, got: $actual)"
        FAIL=$((FAIL + 1))
        FAILED_TESTS+=("$label")
    fi
}

assert_contains() {
    local label="$1" needle="$2" haystack="$3"
    if echo "$haystack" | grep -q "$needle"; then
        echo -e "  ${GREEN}✓${NC} $label  (contains: $needle)"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${NC} $label  (expected to contain: $needle; got: ${haystack:0:120})"
        FAIL=$((FAIL + 1))
        FAILED_TESTS+=("$label")
    fi
}

assert_not_contains() {
    local label="$1" needle="$2" haystack="$3"
    if echo "$haystack" | grep -q "$needle"; then
        echo -e "  ${RED}✗${NC} $label  (unexpectedly contains: $needle)"
        FAIL=$((FAIL + 1))
        FAILED_TESTS+=("$label")
    else
        echo -e "  ${GREEN}✓${NC} $label  (does not contain: $needle)"
        PASS=$((PASS + 1))
    fi
}

echo -e "${CYAN}=== Preflight: artifactory pod reachable ===${NC}"
if ! mock_exec curl -sf "$MOCK/health" >/dev/null; then
    echo -e "${RED}FATAL:${NC} artifactory pod not reachable in $SHARED_NS"
    exit 2
fi
echo "  ok"

echo -e "\n${CYAN}=== Setup: reset mock to known state ===${NC}"
http_body -X POST "$MOCK/__admin__/reset" >/dev/null
echo "  reset issued"

echo -e "\n${CYAN}=== Test 1: GET on unmarked stage → 404 ===${NC}"
assert_eq "GET /__admin__/chain-mark/alpha before POST" \
    "404" "$(http_code "$MOCK/__admin__/chain-mark/alpha")"

echo -e "\n${CYAN}=== Test 2: chain-progress starts empty ===${NC}"
body=$(http_body "$MOCK/__admin__/chain-progress")
assert_contains "chain-progress reports completed=[]" '"completed":\[\]' "$body"

echo -e "\n${CYAN}=== Test 3: POST marks the stage → 200 + body echoes state ===${NC}"
code=$(http_code -X POST "$MOCK/__admin__/chain-mark/alpha")
body=$(http_body -X POST "$MOCK/__admin__/chain-mark/modal")
assert_eq "POST /__admin__/chain-mark/alpha → 200" "200" "$code"
assert_contains "POST modal response includes alpha + modal" '"alpha","modal"' "$body"

echo -e "\n${CYAN}=== Test 4: GET on marked stage → 200 ===${NC}"
assert_eq "GET /__admin__/chain-mark/alpha after POST" \
    "200" "$(http_code "$MOCK/__admin__/chain-mark/alpha")"
assert_eq "GET /__admin__/chain-mark/modal after POST" \
    "200" "$(http_code "$MOCK/__admin__/chain-mark/modal")"

echo -e "\n${CYAN}=== Test 5: GET on OTHER stage still 404 (markers are per-stage) ===${NC}"
assert_eq "GET /__admin__/chain-mark/iota (never marked)" \
    "404" "$(http_code "$MOCK/__admin__/chain-mark/iota")"

echo -e "\n${CYAN}=== Test 6: Invalid stage name rejected with 400 ===${NC}"
assert_eq "POST /__admin__/chain-mark/bogus → 400" \
    "400" "$(http_code -X POST "$MOCK/__admin__/chain-mark/bogus")"
assert_eq "GET /__admin__/chain-mark/bogus → 400" \
    "400" "$(http_code "$MOCK/__admin__/chain-mark/bogus")"

echo -e "\n${CYAN}=== Test 7: Reset clears all markers ===${NC}"
reset_body=$(http_body -X POST "$MOCK/__admin__/reset")
assert_contains "reset response includes chain_markers_deleted" \
    '"chain_markers_deleted"' "$reset_body"
assert_eq "GET /__admin__/chain-mark/alpha after reset → 404" \
    "404" "$(http_code "$MOCK/__admin__/chain-mark/alpha")"
assert_eq "GET /__admin__/chain-mark/modal after reset → 404" \
    "404" "$(http_code "$MOCK/__admin__/chain-mark/modal")"
body=$(http_body "$MOCK/__admin__/chain-progress")
assert_contains "chain-progress empty after reset" '"completed":\[\]' "$body"

echo -e "\n${CYAN}=== Test 8: Attack-surface — PUT to /repos/__chain__/ is rejected ===${NC}"
http_body -X POST "$MOCK/__admin__/chain-mark/alpha" >/dev/null  # mark something
assert_eq "PUT /repos/__chain__/alpha-completed → 404 (fake repo)" \
    "404" "$(http_code -X PUT -H 'Content-Type: text/plain' --data 'x' "$MOCK/repos/__chain__/alpha-completed")"

echo -e "\n${CYAN}=== Test 9: Attack-surface — GET /repos/__chain__/alpha-completed does NOT expose marker ===${NC}"
assert_eq "GET /repos/__chain__/alpha-completed → 404" \
    "404" "$(http_code "$MOCK/repos/__chain__/alpha-completed")"

echo -e "\n${CYAN}=== Test 10: Attack-surface — /repos/__chain__/ listing does NOT leak marker names ===${NC}"
dir_body=$(http_body "$MOCK/repos/__chain__/")
# Listing endpoint returns 200 with empty entries (acceptable); must NOT contain marker names.
assert_not_contains "/repos/__chain__/ listing does not expose 'alpha'" \
    '"alpha-completed"' "$dir_body"
assert_not_contains "/repos/__chain__/ listing does not expose chain-mark path" \
    '"chain-mark"' "$dir_body"

echo -e "\n${CYAN}=== Test 11: Attack-surface — /api/repositories does not expose __chain__ ===${NC}"
repos_body=$(http_body "$MOCK/api/repositories")
assert_not_contains "/api/repositories does not list '__chain__'" \
    '__chain__' "$repos_body"
assert_not_contains "/api/repositories does not reference 'chain-mark'" \
    'chain-mark' "$repos_body"

echo -e "\n${CYAN}=== Test 12: Attack-surface — 404 error payload does not leak admin paths ===${NC}"
err_body=$(http_body "$MOCK/repos/fake-repo/some-key")
assert_not_contains "404 error does not reference '__admin__'" \
    '__admin__' "$err_body"
assert_not_contains "404 error does not reference 'chain-mark'" \
    'chain-mark' "$err_body"

echo -e "\n${CYAN}=== Teardown: reset ===${NC}"
http_body -X POST "$MOCK/__admin__/reset" >/dev/null
echo "  reset issued"

echo
echo "═══════════════════════════════════════════════════════"
echo -e " Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "═══════════════════════════════════════════════════════"
if (( FAIL > 0 )); then
    echo "Failed tests:"
    for t in "${FAILED_TESTS[@]}"; do
        echo "  - $t"
    done
    exit 1
fi
exit 0

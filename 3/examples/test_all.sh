#!/usr/bin/env sh
# Integration test runner — executes all demo scenarios and checks exit codes.
set -u

PASS=0
FAIL=0
HOME_DIR=/tmp/mcpredict-test-$$

setup() {
    mkdir -p "$HOME_DIR/policies" "$HOME_DIR/sessions"
    cp /examples/policies/default.yaml "$HOME_DIR/policies/"
    export MCPREDICT_HOME="$HOME_DIR"
}

teardown() {
    rm -rf "$HOME_DIR"
}

# check <label> <expected_exit> <cmd...>
check() {
    label=$1
    expected=$2
    shift 2

    actual=0
    output=$(eval "$@" 2>&1) || actual=$?

    if [ "$actual" -eq "$expected" ]; then
        printf "  PASS  %s (exit %d)\n" "$label" "$actual"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s — expected exit %d, got %d\n" "$label" "$expected" "$actual"
        printf "        output: %s\n" "$output"
        FAIL=$((FAIL + 1))
    fi
}

# check_contains <label> <expected_substring> <cmd...>
check_contains() {
    label=$1
    substr=$2
    shift 2

    output=$(eval "$@" 2>&1)

    if echo "$output" | grep -qF "$substr"; then
        printf "  PASS  %s (output contains '%s')\n" "$label" "$substr"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s — expected '%s' in output\n" "$label" "$substr"
        printf "        output: %s\n" "$output"
        FAIL=$((FAIL + 1))
    fi
}

echo "=========================================="
echo " mcpredict integration tests"
echo "=========================================="
setup

echo ""
echo "── Scenario 1: Intent mismatch (curl|bash) ──"
check \
    "s1: PreToolUse blocked" 2 \
    "mcpredict pre < /examples/fixtures/scenario1_intent_mismatch.json"

check_contains \
    "s1: block reason mentions pipe-to-shell or intent" "block" \
    "mcpredict pre < /examples/fixtures/scenario1_intent_mismatch.json; true"

echo ""
echo "── Scenario 2: Credential exfiltration ──"
check \
    "s2: PreToolUse blocked" 2 \
    "mcpredict pre < /examples/fixtures/scenario2_credential_exfil.json"

check_contains \
    "s2: block reason mentions DLP" "DLP" \
    "mcpredict pre < /examples/fixtures/scenario2_credential_exfil.json; true"

echo ""
echo "── Scenario 3: Prompt injection in response ──"
check \
    "s3: PostToolUse allowed (exit 0)" 0 \
    "mcpredict post < /examples/fixtures/scenario3_prompt_injection.json"

check_contains \
    "s3: warning emitted to stdout" "SECURITY WARNING" \
    "mcpredict post < /examples/fixtures/scenario3_prompt_injection.json"

echo ""
echo "── Scenario 4: Safe pass-through ──"
check \
    "s4: PreToolUse allowed (exit 0)" 0 \
    "mcpredict pre < /examples/fixtures/scenario4_safe_passthrough.json"

echo ""
echo "── Scenario 5: Base64-decode-pipe-exec bypass ──"
check \
    "s5: bypass base64 blocked (exit 2)" 2 \
    "mcpredict pre < /examples/fixtures/scenario5_bypass_base64.json"

check_contains \
    "s5: block reason mentions bypass or base64" "bypass" \
    "mcpredict pre < /examples/fixtures/scenario5_bypass_base64.json; true"

echo ""
echo "── Scenario 6: Python interpreter shell-escape bypass ──"
check \
    "s6: bypass python blocked (exit 2)" 2 \
    "mcpredict pre < /examples/fixtures/scenario6_bypass_python.json"

check_contains \
    "s6: block reason mentions bypass or interpreter" "bypass" \
    "mcpredict pre < /examples/fixtures/scenario6_bypass_python.json; true"

echo ""
echo "=========================================="
printf " Results: %d passed  /  %d failed\n" "$PASS" "$FAIL"
echo "=========================================="

teardown
[ "$FAIL" -eq 0 ]

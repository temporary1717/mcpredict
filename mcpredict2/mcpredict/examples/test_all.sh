#!/usr/bin/env sh
# Integration test runner — executes all demo scenarios and asserts on the
# stdout JSON contract (Anthropic hook spec).
#
# mcpredict v1.0 returns exit 0 with the verdict carried in
#   hookSpecificOutput.permissionDecision   (PreToolUse)
#   decision                                 (PostToolUse, "block" when blocked)
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

# assert_decision <label> <subcommand> <fixture> <expected-decision>
#   expected-decision: allow | deny | ask | block
assert_decision() {
    label=$1
    sub=$2
    fixture=$3
    expected=$4

    out=$(mcpredict "$sub" < "$fixture" 2>/dev/null || true)

    if [ "$sub" = "post" ]; then
        actual=$(echo "$out" | jq -r '.decision // "allow"')
    else
        actual=$(echo "$out" | jq -r '.hookSpecificOutput.permissionDecision // "allow"')
    fi

    if [ "$actual" = "$expected" ]; then
        printf "  PASS  %s (decision=%s)\n" "$label" "$actual"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s — expected %s, got %s\n" "$label" "$expected" "$actual"
        printf "        output: %s\n" "$out"
        FAIL=$((FAIL + 1))
    fi
}

# assert_reason_contains <label> <subcommand> <fixture> <substring>
assert_reason_contains() {
    label=$1
    sub=$2
    fixture=$3
    substr=$4

    out=$(mcpredict "$sub" < "$fixture" 2>/dev/null || true)

    if [ "$sub" = "post" ]; then
        reason=$(echo "$out" | jq -r '.reason // .hookSpecificOutput.additionalContext // ""')
    else
        reason=$(echo "$out" | jq -r '.hookSpecificOutput.permissionDecisionReason // ""')
    fi

    if echo "$reason" | grep -qiF "$substr"; then
        printf "  PASS  %s (reason contains '%s')\n" "$label" "$substr"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s — expected reason to contain '%s', got: %s\n" "$label" "$substr" "$reason"
        FAIL=$((FAIL + 1))
    fi
}

echo "=========================================="
echo " mcpredict v1.0 integration tests"
echo "=========================================="
setup

echo ""
echo "── Scenario 1: Intent mismatch (curl|bash) ──"
assert_decision        "s1: PreToolUse denied" pre /examples/fixtures/scenario1_intent_mismatch.json deny

echo ""
echo "── Scenario 2: Credential exfiltration ──"
assert_decision        "s2: PreToolUse denied" pre /examples/fixtures/scenario2_credential_exfil.json deny

echo ""
echo "── Scenario 3: Prompt injection in response ──"
assert_decision        "s3: PostToolUse blocked"  post /examples/fixtures/scenario3_prompt_injection.json block
assert_reason_contains "s3: warning context"     post /examples/fixtures/scenario3_prompt_injection.json injection

echo ""
echo "── Scenario 4: Safe pass-through ──"
assert_decision "s4: PreToolUse allowed" pre /examples/fixtures/scenario4_safe_passthrough.json allow

echo ""
echo "── Scenario 5: Base64-decode-pipe-exec bypass ──"
assert_decision        "s5: bypass base64 denied" pre /examples/fixtures/scenario5_bypass_base64.json deny
assert_reason_contains "s5: bypass tag in reason" pre /examples/fixtures/scenario5_bypass_base64.json bypass

echo ""
echo "── Scenario 6: Python interpreter shell-escape bypass ──"
assert_decision        "s6: bypass python denied" pre /examples/fixtures/scenario6_bypass_python.json deny
assert_reason_contains "s6: bypass tag in reason" pre /examples/fixtures/scenario6_bypass_python.json bypass

echo ""
echo "=========================================="
printf " Results: %d passed  /  %d failed\n" "$PASS" "$FAIL"
echo "=========================================="

teardown
[ "$FAIL" -eq 0 ]

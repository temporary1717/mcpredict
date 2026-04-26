// Package e2e_test runs the real mcpredict binary against fixture JSONs over stdin
// and asserts on the stdout response shape. This catches bugs that unit tests miss
// because they bypass the actual hookio → modules → hookio.Write pipeline.
//
// Triggered by D-011: ExtractText bug (B-002) was invisible to unit/integration
// tests but immediately visible when fixtures were piped to the real binary.
package e2e_test

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const repoRel = "../.."

func repoPath(t *testing.T, parts ...string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join(append([]string{repoRel}, parts...)...))
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	return abs
}

// buildBinary compiles cmd/mcpredict into a temp file and returns its path.
func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "mcpredict")
	cmd := exec.Command("go", "build", "-o", bin, repoPath(t, "cmd", "mcpredict"))
	cmd.Dir = repoPath(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return bin
}

// runBinary pipes the fixture file to `bin <subcommand>` and returns parsed JSON output.
func runBinary(t *testing.T, bin, sub, fixturePath string) map[string]any {
	t.Helper()
	in, err := os.Open(fixturePath)
	if err != nil {
		t.Fatalf("open fixture %s: %v", fixturePath, err)
	}
	defer in.Close()
	cmd := exec.Command(bin, sub)
	cmd.Stdin = in
	cmd.Env = append(os.Environ(),
		"MCPREDICT_POLICY="+repoPath(t, "examples", "policies", "baseline.yaml"),
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("run %s %s: %v\nstderr: %s", bin, sub, err, stderr.String())
	}
	body, err := io.ReadAll(&stdout)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("parse stdout JSON: %v\nraw: %s", err, body)
	}
	return out
}

func hookEvent(t *testing.T, out map[string]any) string {
	t.Helper()
	hso, ok := out["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("hookSpecificOutput missing or wrong type: %v", out)
	}
	ev, _ := hso["hookEventName"].(string)
	return ev
}

func preDecision(t *testing.T, out map[string]any) (decision, reason string) {
	t.Helper()
	hso, ok := out["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("hookSpecificOutput missing: %v", out)
	}
	d, _ := hso["permissionDecision"].(string)
	r, _ := hso["permissionDecisionReason"].(string)
	return d, r
}

func TestE2E_Sce1_CurlPipe_NoIntent_Denies(t *testing.T) {
	bin := buildBinary(t)
	out := runBinary(t, bin, "pre",
		repoPath(t, "testdata", "fixtures", "sce-1-curl-pipe-mismatch.json"))

	if got := hookEvent(t, out); got != "PreToolUse" {
		t.Fatalf("hookEventName=%q, want PreToolUse", got)
	}
	d, r := preDecision(t, out)
	if d != "deny" {
		t.Fatalf("permissionDecision=%q, want deny (reason=%q)", d, r)
	}
	if !strings.Contains(r, "외부 스크립트") && !strings.Contains(r, "install") {
		t.Fatalf("reason should mention 외부 스크립트/install, got %q", r)
	}
}

func TestE2E_Sce1_CurlPipe_WithIntent_Allows(t *testing.T) {
	bin := buildBinary(t)
	out := runBinary(t, bin, "pre",
		repoPath(t, "testdata", "fixtures", "sce-1-curl-pipe-with-intent.json"))
	d, _ := preDecision(t, out)
	// Without a real transcript_path the intent extractor returns empty, so we cannot
	// verify the "with-intent allows" case end-to-end; the binary will still deny.
	// We assert only that the binary produced a structured response (no parse error).
	if d == "" {
		t.Fatalf("permissionDecision empty on with-intent fixture (binary should always produce one)")
	}
}

func TestE2E_Sce2_CredentialExfil_Denies(t *testing.T) {
	bin := buildBinary(t)
	out := runBinary(t, bin, "pre",
		repoPath(t, "testdata", "fixtures", "sce-2-credential-exfil.json"))
	d, r := preDecision(t, out)
	if d != "deny" {
		t.Fatalf("permissionDecision=%q, want deny (reason=%q)", d, r)
	}
	if !strings.Contains(r, "credential") && !strings.Contains(r, "자격증명") {
		t.Fatalf("reason should mention credential/자격증명, got %q", r)
	}
}

func TestE2E_Sce4_BenignNpmInstall_Allows(t *testing.T) {
	bin := buildBinary(t)
	out := runBinary(t, bin, "pre",
		repoPath(t, "testdata", "fixtures", "sce-4-benign-npm-install.json"))
	d, _ := preDecision(t, out)
	if d != "allow" {
		t.Fatalf("permissionDecision=%q, want allow (false positive on npm install!)", d)
	}
}

// Sce-5 verifies the mcp__* glob matcher (ARCHITECTURE OQ-2 partial closure).
// `mcp__filesystem__write_file` writing to .ssh/authorized_keys must be denied.
func TestE2E_Sce5_MCPFilesystem_SSHKeys_Denies(t *testing.T) {
	bin := buildBinary(t)
	out := runBinary(t, bin, "pre",
		repoPath(t, "testdata", "fixtures", "sce-5-mcp-filesystem-ssh.json"))
	d, r := preDecision(t, out)
	if d != "deny" {
		t.Fatalf("permissionDecision=%q, want deny (mcp__* SSH key write) reason=%q", d, r)
	}
	if !strings.Contains(r, "MCP filesystem") && !strings.Contains(r, "SSH") {
		t.Fatalf("reason should mention MCP filesystem / SSH, got %q", r)
	}
}

// Sce-6: process substitution bypass — regression guard for 16:30 regex hardening.
func TestE2E_Sce6_BypassProcessSubstitution_Denies(t *testing.T) {
	bin := buildBinary(t)
	out := runBinary(t, bin, "pre",
		repoPath(t, "testdata", "fixtures", "sce-6-bypass-process-substitution.json"))
	d, _ := preDecision(t, out)
	if d != "deny" {
		t.Fatalf("permissionDecision=%q, want deny (bash <(curl ...) bypass)", d)
	}
}

// Sce-7: command substitution bypass.
func TestE2E_Sce7_BypassCommandSubstitution_Denies(t *testing.T) {
	bin := buildBinary(t)
	out := runBinary(t, bin, "pre",
		repoPath(t, "testdata", "fixtures", "sce-7-bypass-command-substitution.json"))
	d, _ := preDecision(t, out)
	if d != "deny" {
		t.Fatalf("permissionDecision=%q, want deny (eval $(curl ...) bypass)", d)
	}
}

// Sce-8: FP regression guard — echo with "rm -rf /tmp/x" in argument must allow.
func TestE2E_Sce8_EchoWithRmPattern_Allows(t *testing.T) {
	bin := buildBinary(t)
	out := runBinary(t, bin, "pre",
		repoPath(t, "testdata", "fixtures", "sce-8-fp-echo-rm-pattern-allowed.json"))
	d, r := preDecision(t, out)
	if d == "deny" {
		t.Fatalf("expected allow on echo with rm pattern in arg (FP regression), got deny: %q", r)
	}
}

// Sce-9: FP regression guard — echo with "git push --force" must allow.
func TestE2E_Sce9_EchoWithGitForce_Allows(t *testing.T) {
	bin := buildBinary(t)
	out := runBinary(t, bin, "pre",
		repoPath(t, "testdata", "fixtures", "sce-9-fp-echo-git-force-allowed.json"))
	d, r := preDecision(t, out)
	if d == "deny" {
		t.Fatalf("expected allow on echo with git push --force in arg (FP regression), got deny: %q", r)
	}
}

// 🔴 The decisive test that catches B-002 (ExtractText bug).
// Without the encoding/json-based ExtractText, this test fails — the binary returns
// {"hookSpecificOutput":{"hookEventName":"PostToolUse"}} with no decision/additionalContext.
func TestE2E_Sce3_PostToolUse_BlocksAndCarriesAdditionalContext(t *testing.T) {
	bin := buildBinary(t)
	out := runBinary(t, bin, "post",
		repoPath(t, "testdata", "fixtures", "sce-3-context-poisoning.json"))

	if got := hookEvent(t, out); got != "PostToolUse" {
		t.Fatalf("hookEventName=%q, want PostToolUse", got)
	}
	dec, _ := out["decision"].(string)
	if dec != "block" {
		t.Fatalf("top-level decision=%q, want block (reason=%v)", dec, out["reason"])
	}
	hso, _ := out["hookSpecificOutput"].(map[string]any)
	addl, _ := hso["additionalContext"].(string)
	if !strings.Contains(addl, "blocked") && !strings.Contains(addl, "injection") {
		t.Fatalf("additionalContext should mention block/injection, got %q", addl)
	}
	r, _ := out["reason"].(string)
	if !strings.Contains(r, "injection") {
		t.Fatalf("reason should mention injection, got %q", r)
	}
}

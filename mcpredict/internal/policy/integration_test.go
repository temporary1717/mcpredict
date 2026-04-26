package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stealien/mcpredict/internal/injection"
	"github.com/stealien/mcpredict/internal/scanner"
	"github.com/stealien/mcpredict/internal/verdict"
)

// fixtureInput mirrors the on-disk fixture shape (HookInput + a few _expected_* fields).
type fixtureInput struct {
	Comment           string          `json:"_comment"`
	ExpectedVerdict   string          `json:"_expected_verdict"`
	ExpectedRuleIDs   []string        `json:"_expected_rule_ids"`
	Intent            string          `json:"_intent"`
	HookEventName     string          `json:"hook_event_name"`
	ToolName          string          `json:"tool_name"`
	ToolInput         json.RawMessage `json:"tool_input"`
	ToolResponse      json.RawMessage `json:"tool_response,omitempty"`
}

func loadFixture(t *testing.T, path string) *fixtureInput {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var f fixtureInput
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse fixture %s: %v", path, err)
	}
	return &f
}

func loadBaselinePolicy(t *testing.T) *Policy {
	t.Helper()
	// repo-relative path: this test file lives in internal/policy → repo root is two up
	p, err := LoadFile(filepath.Join("..", "..", "examples", "policies", "baseline.yaml"))
	if err != nil {
		t.Fatalf("load baseline.yaml: %v", err)
	}
	return p
}

func evaluatePre(t *testing.T, fix *fixtureInput, p *Policy) verdict.Verdict {
	t.Helper()
	args, err := ParseToolInput(fix.ToolInput)
	if err != nil {
		t.Fatalf("parse tool_input: %v", err)
	}
	hasSecret := scanner.Any(string(fix.ToolInput))
	hits := p.Match(CallContext{
		ToolName:  fix.ToolName,
		ToolInput: args,
		Intent:    fix.Intent,
		HasSecret: hasSecret,
	})
	return verdict.Combine(hits...)
}

func TestFixture_Sce1_CurlPipe_NoIntent_Denies(t *testing.T) {
	fix := loadFixture(t, filepath.Join("..", "..", "testdata", "fixtures", "sce-1-curl-pipe-mismatch.json"))
	p := loadBaselinePolicy(t)
	v := evaluatePre(t, fix, p)
	if v.Decision != verdict.Deny {
		t.Fatalf("expected deny, got %s (reason=%q rules=%v)", v.Decision, v.Reason, v.RuleIDs)
	}
	if !containsRule(v.RuleIDs, "bash-curl-pipe-shell") {
		t.Fatalf("expected bash-curl-pipe-shell to fire, got %v", v.RuleIDs)
	}
}

func TestFixture_Sce1_CurlPipe_WithIntent_Allows(t *testing.T) {
	fix := loadFixture(t, filepath.Join("..", "..", "testdata", "fixtures", "sce-1-curl-pipe-with-intent.json"))
	p := loadBaselinePolicy(t)
	v := evaluatePre(t, fix, p)
	if v.Decision == verdict.Deny {
		t.Fatalf("expected allow (intent has install), got deny: %q rules=%v", v.Reason, v.RuleIDs)
	}
}

func TestFixture_Sce2_CredentialExfil_Denies(t *testing.T) {
	fix := loadFixture(t, filepath.Join("..", "..", "testdata", "fixtures", "sce-2-credential-exfil.json"))
	p := loadBaselinePolicy(t)
	v := evaluatePre(t, fix, p)
	if v.Decision != verdict.Deny {
		t.Fatalf("expected deny, got %s (reason=%q rules=%v)", v.Decision, v.Reason, v.RuleIDs)
	}
	// Either secret-in-tool-input or bash-env-cat-and-curl should fire.
	want := []string{"secret-in-tool-input", "bash-env-cat-and-curl"}
	hit := false
	for _, w := range want {
		if containsRule(v.RuleIDs, w) {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("expected one of %v to fire, got %v", want, v.RuleIDs)
	}
}

func TestFixture_Sce4_BenignNpmInstall_Allows(t *testing.T) {
	fix := loadFixture(t, filepath.Join("..", "..", "testdata", "fixtures", "sce-4-benign-npm-install.json"))
	p := loadBaselinePolicy(t)
	v := evaluatePre(t, fix, p)
	if v.Decision == verdict.Deny {
		t.Fatalf("expected allow on benign npm install, got deny: %q rules=%v", v.Reason, v.RuleIDs)
	}
}

func TestFixture_Sce5_MCPFilesystem_SSHKeys_Denies(t *testing.T) {
	fix := loadFixture(t, filepath.Join("..", "..", "testdata", "fixtures", "sce-5-mcp-filesystem-ssh.json"))
	p := loadBaselinePolicy(t)
	v := evaluatePre(t, fix, p)
	if v.Decision != verdict.Deny {
		t.Fatalf("expected deny (mcp__filesystem__* writing .ssh/authorized_keys), got %s (rules=%v reason=%q)",
			v.Decision, v.RuleIDs, v.Reason)
	}
	if !containsRule(v.RuleIDs, "mcp-filesystem-write-ssh-keys") {
		t.Fatalf("expected mcp-filesystem-write-ssh-keys to fire, got %v", v.RuleIDs)
	}
}

// Sce-6: bypass via process substitution `bash <(curl ...)`.
// Regression guard for the 16:30 regex hardening; if anyone reverts the regex to
// only match the pipe form, this test fails.
func TestFixture_Sce6_BypassProcessSubstitution_Denies(t *testing.T) {
	fix := loadFixture(t, filepath.Join("..", "..", "testdata", "fixtures", "sce-6-bypass-process-substitution.json"))
	p := loadBaselinePolicy(t)
	v := evaluatePre(t, fix, p)
	if v.Decision != verdict.Deny {
		t.Fatalf("expected deny on bash <(curl ...), got %s (regex hardening regression?) rules=%v",
			v.Decision, v.RuleIDs)
	}
}

// Sce-7: bypass via command substitution `eval "$(curl ...)"`.
func TestFixture_Sce7_BypassCommandSubstitution_Denies(t *testing.T) {
	fix := loadFixture(t, filepath.Join("..", "..", "testdata", "fixtures", "sce-7-bypass-command-substitution.json"))
	p := loadBaselinePolicy(t)
	v := evaluatePre(t, fix, p)
	if v.Decision != verdict.Deny {
		t.Fatalf("expected deny on eval $(curl ...), got %s rules=%v",
			v.Decision, v.RuleIDs)
	}
}

// Sce-8: FP guard. echo arg containing "rm -rf /tmp/x" must allow.
// Regression guard for 16:35 position-anchored regex; if anyone removes the (?:^|[;&...]) prefix,
// this test fails because the regex would match anywhere again.
func TestFixture_Sce8_EchoWithRmPattern_Allows(t *testing.T) {
	fix := loadFixture(t, filepath.Join("..", "..", "testdata", "fixtures", "sce-8-fp-echo-rm-pattern-allowed.json"))
	p := loadBaselinePolicy(t)
	v := evaluatePre(t, fix, p)
	if v.Decision == verdict.Deny {
		t.Fatalf("expected allow on echo with rm -rf in arg (FP regression), got deny: %q rules=%v",
			v.Reason, v.RuleIDs)
	}
}

// Sce-9: FP guard. echo arg containing "git push --force" must allow.
func TestFixture_Sce9_EchoWithGitForce_Allows(t *testing.T) {
	fix := loadFixture(t, filepath.Join("..", "..", "testdata", "fixtures", "sce-9-fp-echo-git-force-allowed.json"))
	p := loadBaselinePolicy(t)
	v := evaluatePre(t, fix, p)
	if v.Decision == verdict.Deny {
		t.Fatalf("expected allow on echo with git push --force in arg (FP regression), got deny: %q rules=%v",
			v.Reason, v.RuleIDs)
	}
}

func TestFixture_Sce3_PostToolUse_InjectionDetected(t *testing.T) {
	fix := loadFixture(t, filepath.Join("..", "..", "testdata", "fixtures", "sce-3-context-poisoning.json"))
	if len(fix.ToolResponse) == 0 {
		t.Fatal("fixture missing tool_response")
	}
	text := injection.ExtractText(string(fix.ToolResponse))
	hits := injection.Scan(text)
	if len(hits) == 0 {
		t.Fatalf("expected injection hits, got none. extracted=%q", text)
	}
	hasIgnore := false
	hasSystem := false
	for _, h := range hits {
		if h.PatternID == "ignore-previous" {
			hasIgnore = true
		}
		if h.PatternID == "system-tag" {
			hasSystem = true
		}
	}
	if !hasIgnore || !hasSystem {
		t.Fatalf("expected ignore-previous + system-tag patterns, got %v", hits)
	}
}

func containsRule(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

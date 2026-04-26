package verdict

import (
	"strings"
	"testing"
)

func TestCombine_Empty(t *testing.T) {
	v := Combine()
	if v.Decision != Allow {
		t.Fatalf("empty Combine should be Allow, got %s", v.Decision)
	}
}

func TestCombine_AllAllow(t *testing.T) {
	v := Combine(
		Verdict{Decision: Allow},
		Verdict{Decision: Allow, Source: "policy"},
	)
	if v.Decision != Allow {
		t.Fatalf("all allow → Allow, got %s", v.Decision)
	}
	if v.Reason != "" {
		t.Fatalf("allow should have no reason, got %q", v.Reason)
	}
}

func TestCombine_DenyOverridesWarn(t *testing.T) {
	v := Combine(
		Verdict{Decision: Warn, Reason: "soft", RuleIDs: []string{"a"}, Source: "policy"},
		Verdict{Decision: Deny, Reason: "hard", RuleIDs: []string{"b"}, Source: "dlp"},
	)
	if v.Decision != Deny {
		t.Fatalf("deny should win, got %s", v.Decision)
	}
	if !contains(v.RuleIDs, "b") || contains(v.RuleIDs, "a") {
		t.Fatalf("rule_ids should be only deny rules, got %v", v.RuleIDs)
	}
	if !strings.Contains(v.Reason, "hard") || strings.Contains(v.Reason, "soft") {
		t.Fatalf("reason should reflect deny only, got %q", v.Reason)
	}
}

func TestCombine_TwoDenies_MergeAndDedup(t *testing.T) {
	v := Combine(
		Verdict{Decision: Deny, Reason: "policy r1", RuleIDs: []string{"r1"}, Source: "policy"},
		Verdict{Decision: Deny, Reason: "dlp r2", RuleIDs: []string{"r2"}, Source: "dlp"},
		Verdict{Decision: Deny, Reason: "policy dup", RuleIDs: []string{"r1"}, Source: "policy"},
	)
	if v.Decision != Deny {
		t.Fatalf("expected deny, got %s", v.Decision)
	}
	if len(v.RuleIDs) != 2 {
		t.Fatalf("expected 2 unique rule ids, got %v", v.RuleIDs)
	}
	if !strings.Contains(v.Reason, "policy: policy r1") || !strings.Contains(v.Reason, "dlp: dlp r2") {
		t.Fatalf("reason should join sources with reasons, got %q", v.Reason)
	}
	if strings.Count(v.Source, "policy") > 1 {
		t.Fatalf("source should be deduped, got %q", v.Source)
	}
}

func TestDecisionToHookDecision(t *testing.T) {
	cases := []struct {
		d        Decision
		expected string
	}{
		{Allow, "allow"},
		{Warn, "ask"},
		{Deny, "deny"},
		{Decision("unknown"), "allow"},
	}
	for _, c := range cases {
		if got := c.d.ToHookDecision(); got != c.expected {
			t.Fatalf("Decision(%s).ToHookDecision()=%q, want %q", c.d, got, c.expected)
		}
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

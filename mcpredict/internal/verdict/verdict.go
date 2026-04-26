// Package verdict holds the cross-module Decision/Verdict types.
//
// Stub. ARCHITECTURE.md v1.1 §4.2. 팀가 Combine 정교화 예정 (소스별 reason 연결, A10).
package verdict

import "strings"

type Decision string

const (
	Allow Decision = "allow"
	Warn  Decision = "warn"
	Deny  Decision = "deny"
)

type Verdict struct {
	Decision Decision
	Reason   string
	RuleIDs  []string
	Source   string // policy | dlp | injection
}

// rank: deny > warn > allow.
func (d Decision) rank() int {
	switch d {
	case Deny:
		return 2
	case Warn:
		return 1
	default:
		return 0
	}
}

// Combine selects the strictest decision. Ties merge RuleIDs and concatenate sources/reasons.
// 추가 제안 A10: 동률 deny 다중 source일 때 reason은 "src1: r1; src2: r2".
// 팀 정교화: RuleIDs / sources 중복 제거, 빈 reason은 출력 제외.
func Combine(vs ...Verdict) Verdict {
	if len(vs) == 0 {
		return Verdict{Decision: Allow}
	}
	out := Verdict{Decision: Allow}
	var reasons []string
	var sources []string
	for _, v := range vs {
		if v.Decision == "" {
			continue
		}
		if v.Decision.rank() > out.Decision.rank() {
			out = Verdict{Decision: v.Decision}
			reasons = reasons[:0]
			sources = sources[:0]
		}
		if v.Decision.rank() == out.Decision.rank() && v.Decision != Allow {
			out.RuleIDs = append(out.RuleIDs, v.RuleIDs...)
			if v.Reason != "" {
				if v.Source != "" {
					reasons = append(reasons, v.Source+": "+v.Reason)
				} else {
					reasons = append(reasons, v.Reason)
				}
			}
			if v.Source != "" {
				sources = append(sources, v.Source)
			}
		}
	}
	out.RuleIDs = dedupStrings(out.RuleIDs)
	out.Reason = strings.Join(reasons, "; ")
	out.Source = strings.Join(dedupStrings(sources), ",")
	return out
}

func dedupStrings(in []string) []string {
	if len(in) <= 1 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// ToHookDecision maps Verdict.Decision to Claude Code permissionDecision string.
func (d Decision) ToHookDecision() string {
	switch d {
	case Deny:
		return "deny"
	case Warn:
		return "ask"
	default:
		return "allow"
	}
}

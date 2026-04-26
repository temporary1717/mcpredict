// Package policy implements the YAML policy loader and rule matcher.
//
// ARCHITECTURE.md v1.1 §4.3. Round 1 합의 + V2 발견(description_regex) 반영.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/stealien/mcpredict/internal/verdict"
	"gopkg.in/yaml.v3"
)

// IntentCheck — 직전 assistant 텍스트 매칭 조건.
type IntentCheck struct {
	Mode      string   `yaml:"mode"` // required_keyword | absent_keyword | none
	Keywords  []string `yaml:"keywords"`
	Threshold int      `yaml:"threshold"`
}

// SequencePrior — 동일 세션의 직전 N개 호출 매칭.
type SequencePrior struct {
	Tool          string `yaml:"tool"`
	FilePathRegex string `yaml:"file_path_regex"`
	Within        int    `yaml:"within"`

	pathRe *regexp.Regexp
}

// When — 도구 호출 매칭 조건.
type When struct {
	Tool             any            `yaml:"tool"` // string | []string
	CommandRegex     string         `yaml:"command_regex,omitempty"`
	FilePathRegex    string         `yaml:"file_path_regex,omitempty"`
	URLRegex         string         `yaml:"url_regex,omitempty"`
	DescriptionRegex string         `yaml:"description_regex,omitempty"`
	ContainsSecret   bool           `yaml:"contains_secret,omitempty"`
	SequencePrior    *SequencePrior `yaml:"sequence_prior,omitempty"`

	tools  []string // normalized tool list ("any" → ["any"])
	cmdRe  *regexp.Regexp
	pathRe *regexp.Regexp
	urlRe  *regexp.Regexp
	descRe *regexp.Regexp
}

// Rule — 정책 단위.
type Rule struct {
	ID          string       `yaml:"id"`
	Description string       `yaml:"description,omitempty"`
	When        When         `yaml:"when"`
	IntentCheck *IntentCheck `yaml:"intent_check,omitempty"`
	Action      string       `yaml:"action"` // allow | warn | deny
	Reason      string       `yaml:"reason"`
}

// Policy — 정책 파일 한 개의 표현.
type Policy struct {
	Version int    `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// Load parses YAML bytes into a Policy and pre-compiles regexes.
func Load(data []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("policy: parse: %w", err)
	}
	for i := range p.Rules {
		if err := compileRule(&p.Rules[i]); err != nil {
			return nil, fmt.Errorf("policy: rule %s: %w", p.Rules[i].ID, err)
		}
	}
	return &p, nil
}

// LoadFile reads a YAML file from disk.
func LoadFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Load(data)
}

func compileRule(r *Rule) error {
	switch t := r.When.Tool.(type) {
	case string:
		r.When.tools = []string{t}
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				r.When.tools = append(r.When.tools, s)
			}
		}
	case nil:
		r.When.tools = []string{"any"}
	default:
		return fmt.Errorf("when.tool unsupported type %T", t)
	}
	var err error
	if r.When.CommandRegex != "" {
		if r.When.cmdRe, err = regexp.Compile(r.When.CommandRegex); err != nil {
			return fmt.Errorf("command_regex: %w", err)
		}
	}
	if r.When.FilePathRegex != "" {
		if r.When.pathRe, err = regexp.Compile(r.When.FilePathRegex); err != nil {
			return fmt.Errorf("file_path_regex: %w", err)
		}
	}
	if r.When.URLRegex != "" {
		if r.When.urlRe, err = regexp.Compile(r.When.URLRegex); err != nil {
			return fmt.Errorf("url_regex: %w", err)
		}
	}
	if r.When.DescriptionRegex != "" {
		if r.When.descRe, err = regexp.Compile(r.When.DescriptionRegex); err != nil {
			return fmt.Errorf("description_regex: %w", err)
		}
	}
	if r.When.SequencePrior != nil && r.When.SequencePrior.FilePathRegex != "" {
		if r.When.SequencePrior.pathRe, err = regexp.Compile(r.When.SequencePrior.FilePathRegex); err != nil {
			return fmt.Errorf("sequence_prior.file_path_regex: %w", err)
		}
	}
	return nil
}

// PriorCall — 동일 세션의 직전 도구 호출 (sequence_prior 평가용).
type PriorCall struct {
	ToolName  string
	ToolInput map[string]any
}

// CallContext — 매처에 전달되는 한 호출의 모든 정보.
type CallContext struct {
	ToolName   string
	ToolInput  map[string]any
	Intent     string      // 직전 assistant text (소문자 비교)
	HasSecret  bool        // scanner.Scan 결과 any
	PriorCalls []PriorCall // 직전 N개 (최신이 마지막)
}

// ParseToolInput unmarshals raw tool_input JSON into a map.
func ParseToolInput(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	m := map[string]any{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("policy: tool_input parse: %w", err)
	}
	return m, nil
}

// Match — 모든 룰을 평가하여 매치된 verdict 슬라이스를 반환.
func (p *Policy) Match(ctx CallContext) []verdict.Verdict {
	var hits []verdict.Verdict
	for i := range p.Rules {
		r := &p.Rules[i]
		if !r.matches(ctx) {
			continue
		}
		hits = append(hits, verdict.Verdict{
			Decision: actionDecision(r.Action),
			Reason:   r.Reason,
			RuleIDs:  []string{r.ID},
			Source:   "policy",
		})
	}
	return hits
}

func (r *Rule) matches(ctx CallContext) bool {
	if !toolMatches(r.When.tools, ctx.ToolName) {
		return false
	}
	if r.When.cmdRe != nil {
		cmd, _ := ctx.ToolInput["command"].(string)
		if !r.When.cmdRe.MatchString(cmd) {
			return false
		}
	}
	if r.When.pathRe != nil {
		path, _ := ctx.ToolInput["file_path"].(string)
		if !r.When.pathRe.MatchString(path) {
			return false
		}
	}
	if r.When.urlRe != nil {
		url, _ := ctx.ToolInput["url"].(string)
		if !r.When.urlRe.MatchString(url) {
			return false
		}
	}
	if r.When.descRe != nil {
		desc, _ := ctx.ToolInput["description"].(string)
		if !r.When.descRe.MatchString(desc) {
			return false
		}
	}
	if r.When.ContainsSecret && !ctx.HasSecret {
		return false
	}
	if r.When.SequencePrior != nil && !sequenceMatches(r.When.SequencePrior, ctx.PriorCalls) {
		return false
	}
	if r.IntentCheck != nil && !intentTriggers(r.IntentCheck, ctx.Intent) {
		return false
	}
	return true
}

func toolMatches(allowed []string, got string) bool {
	for _, t := range allowed {
		if t == "any" || t == got {
			return true
		}
		// mcp__* glob support (suffix wildcard for MCP tools)
		if strings.HasSuffix(t, "*") && strings.HasPrefix(got, strings.TrimSuffix(t, "*")) {
			return true
		}
	}
	return false
}

func sequenceMatches(sp *SequencePrior, prior []PriorCall) bool {
	within := sp.Within
	if within <= 0 {
		within = 5
	}
	start := len(prior) - within
	if start < 0 {
		start = 0
	}
	for _, p := range prior[start:] {
		if sp.Tool != "" && sp.Tool != p.ToolName {
			continue
		}
		if sp.pathRe != nil {
			path, _ := p.ToolInput["file_path"].(string)
			if !sp.pathRe.MatchString(path) {
				continue
			}
		}
		return true
	}
	return false
}

// intentTriggers returns true if the rule should be applied given the intent.
//
// required_keyword / absent_keyword 둘 다 "키워드가 의도에 충분히 표명되지 않으면 룰 적용"으로 동작.
// (기획상 의미 차이는 있으나 9시간 MVP에선 단일 동작. ARCHITECTURE §4.3 코멘트 참조.)
func intentTriggers(ic *IntentCheck, intent string) bool {
	if ic.Mode == "" || ic.Mode == "none" {
		return true
	}
	threshold := ic.Threshold
	if threshold <= 0 {
		threshold = 1
	}
	intentLower := strings.ToLower(intent)
	cnt := 0
	for _, kw := range ic.Keywords {
		if strings.Contains(intentLower, strings.ToLower(kw)) {
			cnt++
		}
	}
	switch ic.Mode {
	case "required_keyword", "absent_keyword":
		return cnt < threshold
	}
	return true
}

func actionDecision(a string) verdict.Decision {
	switch a {
	case "deny":
		return verdict.Deny
	case "warn":
		return verdict.Warn
	default:
		return verdict.Allow
	}
}

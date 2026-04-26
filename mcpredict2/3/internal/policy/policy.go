package policy

import (
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Action is what to do when a rule matches.
type Action string

const (
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
	ActionWarn  Action = "warn"
)

// Rule is one entry in a policy YAML file.
type Rule struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Event       string `yaml:"event"` // "PreToolUse" | "PostToolUse" | "*" | ""
	ToolPattern string `yaml:"tool_pattern"`
	InputPattern string `yaml:"input_pattern"`
	Action      Action `yaml:"action"`
	Reason      string `yaml:"reason"`

	toolRe  *regexp.Regexp
	inputRe *regexp.Regexp
}

type policyFile struct {
	Version string `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// Engine holds compiled rules.
type Engine struct {
	rules []Rule
}

// Load reads all *.yaml files from dir and merges their rules.
// Missing dir is not an error — returns an empty engine.
func Load(dir string) (*Engine, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return &Engine{}, nil
	}

	var rules []Rule
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var pf policyFile
		if err := yaml.Unmarshal(data, &pf); err != nil {
			continue
		}
		for i := range pf.Rules {
			r := &pf.Rules[i]
			if r.ToolPattern != "" {
				r.toolRe, _ = regexp.Compile(r.ToolPattern)
			}
			if r.InputPattern != "" {
				r.inputRe, _ = regexp.Compile(r.InputPattern)
			}
		}
		rules = append(rules, pf.Rules...)
	}
	return &Engine{rules: rules}, nil
}

// MatchResult is the outcome of evaluating all policy rules.
type MatchResult struct {
	Action  Action
	Reason  string
	Matched []string
}

// Evaluate returns the first blocking/warning rule that matches, or allow.
func (e *Engine) Evaluate(event, toolName, toolInput string) MatchResult {
	for _, r := range e.rules {
		if r.Event != "" && r.Event != "*" && r.Event != event {
			continue
		}
		if r.toolRe != nil && !r.toolRe.MatchString(toolName) {
			continue
		}
		if r.inputRe != nil && !r.inputRe.MatchString(toolInput) {
			continue
		}
		if r.Action == ActionBlock || r.Action == ActionWarn {
			return MatchResult{
				Action:  r.Action,
				Reason:  r.Reason,
				Matched: []string{r.Name},
			}
		}
	}
	return MatchResult{Action: ActionAllow}
}

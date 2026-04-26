package main

import (
	"os"
	"path/filepath"
	"time"

	"github.com/stealien/mcpredict/internal/audit"
	"github.com/stealien/mcpredict/internal/hookio"
	"github.com/stealien/mcpredict/internal/intent"
	"github.com/stealien/mcpredict/internal/policy"
	"github.com/stealien/mcpredict/internal/scanner"
	"github.com/stealien/mcpredict/internal/verdict"
)

// runPre handles a PreToolUse hook invocation.
//
// Pipeline (ARCHITECTURE.md §2.1):
//  1. read stdin → HookInput
//  2. extract assistant intent from transcript JSONL
//  3. scanner.Scan on serialized tool_input → DLP signals
//  4. policy.Match with intent + tool_input + has_secret
//  5. verdict.Combine
//  6. session/audit
//  7. write stdout HookOutput
func runPre() int {
	start := time.Now()

	in, err := hookio.Read(os.Stdin)
	if err != nil {
		debugf("hookio.Read: %v", err)
		failSafe(hookio.EventPre, "input parse error: "+err.Error())
		return 0
	}

	intentRes, err := intent.Extract(in.TranscriptPath)
	if err != nil {
		debugf("intent.Extract: %v", err)
		intentRes = &intent.Result{Empty: true}
	}

	var verdicts []verdict.Verdict

	// (3a) DLP — secrets/PII in tool_input.
	toolInputStr := string(in.ToolInput)
	dlpHits := scanner.Scan(toolInputStr)
	if len(dlpHits) > 0 {
		ids := make([]string, 0, len(dlpHits))
		for _, h := range dlpHits {
			ids = append(ids, h.PatternID)
		}
		verdicts = append(verdicts, verdict.Verdict{
			Decision: verdict.Deny,
			Reason:   "credential or PII pattern in tool_input",
			RuleIDs:  ids,
			Source:   "dlp",
		})
	}

	// (3b) Bypass detection — interpreter escape, base64, IFS, ANSI hex,
	// path traversal, env exec, Cyrillic/zero-width Unicode.
	if bypassHits := scanner.ScanBypass(toolInputStr); len(bypassHits) > 0 {
		ids := make([]string, 0, len(bypassHits))
		for _, h := range bypassHits {
			ids = append(ids, "bypass."+h.Name)
		}
		verdicts = append(verdicts, verdict.Verdict{
			Decision: verdict.Deny,
			Reason:   "shell evasion / bypass technique in tool_input",
			RuleIDs:  ids,
			Source:   "bypass",
		})
	}
	if uniHits := scanner.ScanUnicodeBypass(toolInputStr); len(uniHits) > 0 {
		ids := make([]string, 0, len(uniHits))
		for _, n := range uniHits {
			ids = append(ids, "bypass."+n)
		}
		verdicts = append(verdicts, verdict.Verdict{
			Decision: verdict.Warn,
			Reason:   "Unicode homoglyph or zero-width character in tool_input",
			RuleIDs:  ids,
			Source:   "bypass",
		})
	}

	// (4) Policy match.
	if pol := loadPolicy(); pol != nil {
		toolInputMap, _ := policy.ParseToolInput(in.ToolInput)
		ctx := policy.CallContext{
			ToolName:  in.ToolName,
			ToolInput: toolInputMap,
			Intent:    intentRes.Text,
			HasSecret: len(dlpHits) > 0,
		}
		verdicts = append(verdicts, pol.Match(ctx)...)
	}

	// (5) combine.
	v := verdict.Combine(verdicts...)

	// (6) state.
	auditLog, sess := openState()
	if sess != nil {
		_ = sess.Touch(in.SessionID, in.CWD)
		_ = sess.Record(in.SessionID, in.HookEventName, in.ToolName, string(v.Decision), v.Reason)
		_ = sess.Close()
	}
	if auditLog != nil {
		auditLog.Append(audit.Record{
			SessionID:     in.SessionID,
			HookEvent:     in.HookEventName,
			ToolName:      in.ToolName,
			Verdict:       string(v.Decision),
			Source:        v.Source,
			RuleIDs:       v.RuleIDs,
			Reason:        v.Reason,
			IntentHash:    audit.Hash([]byte(intentRes.Text)),
			ToolInputHash: audit.Hash(audit.CanonicalJSON(in.ToolInput)),
			LatencyMS:     time.Since(start).Milliseconds(),
		})
	}

	// (7) stdout.
	if err := hookio.Write(os.Stdout, hookio.EventPre, v.Decision.ToHookDecision(), v.Reason, ""); err != nil {
		debugf("hookio.Write: %v", err)
	}
	return 0
}

// loadPolicy resolves a single policy file (later: directory of YAMLs).
//
// Search order:
//  1. $MCPREDICT_POLICY (explicit path, override)
//  2. $MCPREDICT_HOME/policies/baseline.yaml (or ~/.mcpredict/policies/baseline.yaml)
//  3. ./examples/policies/baseline.yaml (dev mode — when running from repo)
func loadPolicy() *policy.Policy {
	if p := os.Getenv("MCPREDICT_POLICY"); p != "" {
		return tryLoad(p)
	}
	dir, err := stateDir()
	if err == nil {
		if p := tryLoad(filepath.Join(dir, "policies", "baseline.yaml")); p != nil {
			return p
		}
	}
	if exe, err := os.Executable(); err == nil {
		base := filepath.Dir(exe)
		if p := tryLoad(filepath.Join(base, "examples", "policies", "baseline.yaml")); p != nil {
			return p
		}
	}
	if p := tryLoad("examples/policies/baseline.yaml"); p != nil {
		return p
	}
	debugf("no policy found")
	return nil
}

func tryLoad(path string) *policy.Policy {
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	p, err := policy.LoadFile(path)
	if err != nil {
		debugf("policy load %s: %v", path, err)
		return nil
	}
	return p
}

// failSafe handles unrecoverable errors per §7. Default = warn (ask the user).
func failSafe(event, reason string) {
	switch failMode() {
	case "open":
		_ = hookio.Write(os.Stdout, event, hookio.DecisionAllow, "", "")
	case "closed":
		_ = hookio.Write(os.Stdout, event, hookio.DecisionDeny, "mcpredict failed; closed mode → deny: "+reason, "")
	default:
		_ = hookio.Write(os.Stdout, event, hookio.DecisionAsk, "mcpredict failed; warn mode → ask: "+reason, "")
	}
}

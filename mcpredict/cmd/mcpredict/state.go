package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/stealien/mcpredict/internal/audit"
	"github.com/stealien/mcpredict/internal/session"
)

// stateDir returns the mcpredict state directory ($MCPREDICT_HOME or ~/.mcpredict).
func stateDir() (string, error) {
	if d := os.Getenv("MCPREDICT_HOME"); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".mcpredict"), nil
}

// openState opens audit logger and SQLite recorder, ensuring the dir exists.
// All callers are PreToolUse / PostToolUse hooks — failure must not block tool
// execution per §10. We return nil pointers on error and let callers proceed.
func openState() (*audit.Logger, *session.Recorder) {
	dir, err := stateDir()
	if err != nil {
		debugf("stateDir: %v", err)
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		debugf("mkdir state: %v", err)
		return nil, nil
	}
	logger := audit.NewLogger(filepath.Join(dir, "audit.jsonl"))
	rec, err := session.Open(filepath.Join(dir, "session.db"))
	if err != nil {
		debugf("session.Open: %v", err)
		return logger, nil
	}
	return logger, rec
}

func debugf(format string, args ...any) {
	if os.Getenv("MCPREDICT_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[mcpredict] "+format+"\n", args...)
	}
}

// failMode returns the configured fail-safe behavior (§7).
func failMode() string {
	m := os.Getenv("MCPREDICT_FAIL_MODE")
	switch m {
	case "open", "closed", "warn":
		return m
	default:
		return "warn"
	}
}

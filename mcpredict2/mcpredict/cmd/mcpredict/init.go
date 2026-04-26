package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// runInit creates ~/.mcpredict layout: state dir, policies/, audit.jsonl, session.db schema.
func runInit() int {
	dir, err := stateDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: stateDir: %v\n", err)
		return 1
	}
	for _, sub := range []string{"", "policies"} {
		p := filepath.Join(dir, sub)
		if err := os.MkdirAll(p, 0o700); err != nil {
			fmt.Fprintf(os.Stderr, "init: mkdir %s: %v\n", p, err)
			return 1
		}
	}
	// Touch audit.jsonl with 0600 perms.
	auditPath := filepath.Join(dir, "audit.jsonl")
	f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init: create audit.jsonl: %v\n", err)
		return 1
	}
	f.Close()

	// Initialize SQLite schema by opening the recorder once.
	_, sess := openState()
	if sess != nil {
		sess.Close()
	}

	fmt.Printf("mcpredict initialized at %s\n", dir)
	fmt.Println("  policies/   (drop YAML files here)")
	fmt.Println("  session.db  (SQLite — auto-managed)")
	fmt.Println("  audit.jsonl (append-only audit log, 0600)")
	return 0
}

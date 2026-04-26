package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mcpredict/internal/dashboard"
)

// runDashboard serves the audit log over HTTP for live observation.
//
// Usage:
//
//	mcpredict dashboard [addr]
//
// addr defaults to "127.0.0.1:8080". Bare port ("8080") is accepted.
func runDashboard() int {
	addr := "127.0.0.1:8080"
	if len(os.Args) >= 3 {
		a := os.Args[2]
		if !strings.Contains(a, ":") {
			addr = "127.0.0.1:" + a
		} else {
			addr = a
		}
	}
	dir, err := stateDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcpredict dashboard: stateDir:", err)
		return 1
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "mcpredict dashboard: mkdir:", err)
		return 1
	}
	auditPath := filepath.Join(dir, "audit.jsonl")
	if err := dashboard.New(auditPath).Start(addr); err != nil {
		fmt.Fprintln(os.Stderr, "mcpredict dashboard:", err)
		return 1
	}
	return 0
}

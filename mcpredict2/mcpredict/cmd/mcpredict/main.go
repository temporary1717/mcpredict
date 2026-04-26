// Command mcpredict is the Claude Code hook handler binary.
//
// Subcommand routing per ARCHITECTURE.md v1.1 §3 (A1).
// Usage:
//
//	mcpredict pre        # PreToolUse hook (stdin JSON in, stdout JSON out)
//	mcpredict post       # PostToolUse hook
//	mcpredict init       # initialize ~/.mcpredict/{session.db,policies/}
//	mcpredict version
package main

import (
	"fmt"
	"os"
)

const version = "0.1.0-mvp"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(64)
	}
	switch os.Args[1] {
	case "pre":
		os.Exit(runPre())
	case "post":
		os.Exit(runPost())
	case "init":
		os.Exit(runInit())
	case "dashboard":
		os.Exit(runDashboard())
	case "version", "-v", "--version":
		fmt.Println("mcpredict", version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "mcpredict: unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(64)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `mcpredict — Claude Code agent guardrail (Pre/PostToolUse hook handler).

USAGE:
  mcpredict pre              PreToolUse  hook entry  (stdin JSON in, stdout JSON out)
  mcpredict post             PostToolUse hook entry
  mcpredict init             initialize ~/.mcpredict layout
  mcpredict dashboard [addr] serve audit log over HTTP (default 127.0.0.1:8080)
  mcpredict version

ENV:
  MCPREDICT_HOME       state dir (default: ~/.mcpredict)
  MCPREDICT_FAIL_MODE  open|closed|warn  (default: warn)
  MCPREDICT_DEBUG      1 to enable stderr debug logs and raw_input_path capture

`)
}

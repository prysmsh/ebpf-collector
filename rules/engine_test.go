package rules

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestCELEnvironment(t *testing.T) {
	env, err := celEnvironment()
	if err != nil {
		t.Fatalf("celEnvironment() error: %v", err)
	}
	if env == nil {
		t.Fatal("celEnvironment() returned nil")
	}
}

func TestExpandMacros(t *testing.T) {
	macros := map[string]string{
		"shell_procs": "proc.name in ['sh', 'bash', 'zsh']",
	}

	input := "evt.type == 'execve' && shell_procs"
	result := expandMacros(input, macros)
	expected := "evt.type == 'execve' && (proc.name in ['sh', 'bash', 'zsh'])"
	if result != expected {
		t.Errorf("expandMacros:\n  got:  %s\n  want: %s", result, expected)
	}
}

func TestExpandLists(t *testing.T) {
	lists := map[string][]string{
		"c2_ports": {"4444", "5555", "6666"},
	}

	input := "net.dst_port in (c2_ports)"
	result := expandLists(input, lists)
	expected := "net.dst_port in ['4444', '5555', '6666']"
	if result != expected {
		t.Errorf("expandLists:\n  got:  %s\n  want: %s", result, expected)
	}
}

func TestTranslateFalcoOps(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "evt.type = 'execve' and proc.name = 'bash'",
			expected: "evt.type == 'execve' && proc.name == 'bash'",
		},
		{
			input:    "not shell_procs or proc.uid = 0",
			expected: "! shell_procs || proc.uid == 0",
		},
	}

	for _, tt := range tests {
		result := translateFalcoOps(tt.input)
		if result != tt.expected {
			t.Errorf("translateFalcoOps(%q):\n  got:  %s\n  want: %s", tt.input, result, tt.expected)
		}
	}
}

func TestTranslateContains(t *testing.T) {
	input := "proc.cmdline contains '/dev/tcp'"
	result := translateContains(input)
	expected := "proc.cmdline.contains('/dev/tcp')"
	if result != expected {
		t.Errorf("translateContains(%q):\n  got:  %s\n  want: %s", input, result, expected)
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		s       string
		pattern string
		want    bool
	}{
		{"hello", "hello", true},
		{"hello", "hell*", true},
		{"hello", "*llo", true},
		{"hello", "h?llo", true},
		{"hello", "h*o", true},
		{"hello", "world", false},
		{"hello", "h??lo", true},
		{"", "*", true},
		{"", "", true},
		{"abc", "a*c", true},
		{"nginx:1.25", "nginx:*", true},
	}

	for _, tt := range tests {
		got := matchGlob(tt.s, tt.pattern)
		if got != tt.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.s, tt.pattern, got, tt.want)
		}
	}
}

func TestEngineEvaluate(t *testing.T) {
	// Create a temp directory with a simple test rule
	dir := t.TempDir()
	ruleContent := `
- rule: Test shell execution
  condition: evt.type == 'execve' && proc.name == 'bash'
  output: "Shell %proc.name% executed (pid=%proc.pid%)"
  priority: WARNING
  tags: [test]
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(ruleContent), 0644); err != nil {
		t.Fatalf("write rule file: %v", err)
	}

	var mu sync.Mutex
	var alerts []Alert

	logger := log.New(os.Stderr, "[test] ", 0)
	engine, err := NewEngine(dir, "", logger, func(alert Alert) {
		mu.Lock()
		alerts = append(alerts, alert)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	if engine.RuleCount() != 1 {
		t.Fatalf("expected 1 rule, got %d", engine.RuleCount())
	}

	// Test matching event
	vars := EventVars{
		EvtType:   "execve",
		EvtSource: "ebpf",
		ProcName:  "bash",
		ProcPID:   1234,
	}

	matches := engine.Evaluate(vars)
	if matches != 1 {
		t.Errorf("expected 1 match, got %d", matches)
	}

	mu.Lock()
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(alerts))
	} else {
		if alerts[0].RuleName != "Test shell execution" {
			t.Errorf("unexpected rule name: %s", alerts[0].RuleName)
		}
		if alerts[0].Priority != PriorityWarning {
			t.Errorf("unexpected priority: %v", alerts[0].Priority)
		}
	}
	mu.Unlock()

	// Test non-matching event
	vars2 := EventVars{
		EvtType:   "execve",
		EvtSource: "ebpf",
		ProcName:  "ls",
		ProcPID:   5678,
	}

	matches2 := engine.Evaluate(vars2)
	if matches2 != 0 {
		t.Errorf("expected 0 matches, got %d", matches2)
	}
}

func TestEngineWithMacros(t *testing.T) {
	dir := t.TempDir()
	ruleContent := `
- macro: shell_procs
  condition: proc.name in ['sh', 'bash', 'zsh']

- rule: Shell detected
  condition: evt.type == 'execve' && shell_procs
  output: "Shell %proc.name%"
  priority: WARNING
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(ruleContent), 0644); err != nil {
		t.Fatal(err)
	}

	var alerts []Alert
	var mu sync.Mutex

	logger := log.New(os.Stderr, "[test] ", 0)
	engine, err := NewEngine(dir, "", logger, func(alert Alert) {
		mu.Lock()
		alerts = append(alerts, alert)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	// bash should match
	engine.Evaluate(EventVars{EvtType: "execve", EvtSource: "ebpf", ProcName: "bash"})
	// zsh should match
	engine.Evaluate(EventVars{EvtType: "execve", EvtSource: "ebpf", ProcName: "zsh"})
	// ls should not match
	engine.Evaluate(EventVars{EvtType: "execve", EvtSource: "ebpf", ProcName: "ls"})

	mu.Lock()
	if len(alerts) != 2 {
		t.Errorf("expected 2 alerts, got %d", len(alerts))
	}
	mu.Unlock()
}

func TestEngineExceptions(t *testing.T) {
	dir := t.TempDir()
	ruleContent := `
- rule: File access
  condition: evt.type == 'open' && file.path == '/etc/shadow'
  output: "Shadow access by %proc.name%"
  priority: ALERT
  exceptions:
    - name: known_readers
      fields: [proc.name]
      comps: ["="]
      values:
        - [passwd]
        - [login]
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(ruleContent), 0644); err != nil {
		t.Fatal(err)
	}

	var alerts []Alert
	var mu sync.Mutex

	logger := log.New(os.Stderr, "[test] ", 0)
	engine, err := NewEngine(dir, "", logger, func(alert Alert) {
		mu.Lock()
		alerts = append(alerts, alert)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	// passwd reading /etc/shadow → excepted, no alert
	engine.Evaluate(EventVars{EvtType: "open", EvtSource: "ebpf", ProcName: "passwd", FilePath: "/etc/shadow"})
	// cat reading /etc/shadow → not excepted, alert
	engine.Evaluate(EventVars{EvtType: "open", EvtSource: "ebpf", ProcName: "cat", FilePath: "/etc/shadow"})

	mu.Lock()
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert (cat only), got %d", len(alerts))
	}
	mu.Unlock()
}

func TestEngineScope(t *testing.T) {
	dir := t.TempDir()
	ruleContent := `
- rule: Scoped rule
  condition: evt.type == 'execve' && proc.name == 'bash'
  output: "Bash in prod"
  priority: WARNING
  scope:
    namespaces: [production, staging]
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(ruleContent), 0644); err != nil {
		t.Fatal(err)
	}

	var alerts []Alert
	var mu sync.Mutex

	logger := log.New(os.Stderr, "[test] ", 0)
	engine, err := NewEngine(dir, "", logger, func(alert Alert) {
		mu.Lock()
		alerts = append(alerts, alert)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	// production namespace → matches scope
	engine.Evaluate(EventVars{EvtType: "execve", EvtSource: "ebpf", ProcName: "bash", K8sNS: "production"})
	// development namespace → outside scope
	engine.Evaluate(EventVars{EvtType: "execve", EvtSource: "ebpf", ProcName: "bash", K8sNS: "development"})

	mu.Lock()
	if len(alerts) != 1 {
		t.Errorf("expected 1 alert (production only), got %d", len(alerts))
	}
	mu.Unlock()
}

func TestOutputRendering(t *testing.T) {
	e := &Engine{logger: log.New(os.Stderr, "", 0)}

	vars := EventVars{
		ProcName:      "bash",
		ProcPID:       1234,
		ContainerName: "web-app",
	}

	output := e.renderOutput("Shell %proc.name% (pid=%proc.pid%) in container=%container.name%", vars)
	expected := "Shell bash (pid=1234) in container=web-app"
	if output != expected {
		t.Errorf("renderOutput:\n  got:  %s\n  want: %s", output, expected)
	}
}

func TestParsePriority(t *testing.T) {
	tests := []struct {
		input string
		want  Priority
	}{
		{"CRITICAL", PriorityCritical},
		{"critical", PriorityCritical},
		{"WARNING", PriorityWarning},
		{"warn", PriorityWarning},
		{"ALERT", PriorityAlert},
		{"INFO", PriorityInformational},
		{"unknown", PriorityWarning},
	}

	for _, tt := range tests {
		got := ParsePriority(tt.input)
		if got != tt.want {
			t.Errorf("ParsePriority(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

package rules

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
)

// CompiledRule is a rule whose condition has been parsed and compiled into a
// CEL program ready for evaluation.
type CompiledRule struct {
	Rule    Rule
	Program cel.Program
}

// Engine loads rules from YAML, compiles them into CEL programs, evaluates
// incoming events against all active rules, and supports hot-reload.
type Engine struct {
	mu    sync.RWMutex
	rules []CompiledRule
	env   *cel.Env

	loader *Loader
	logger *log.Logger

	// onAlert is called for every rule match. The caller wires this to the
	// existing threat detection pipeline.
	onAlert func(Alert)
}

// NewEngine creates a rules engine. rulesDir is the path to the directory
// containing built-in YAML rules. customDir is an optional user-supplied
// rules directory (may be empty). onAlert is invoked for every match.
func NewEngine(rulesDir, customDir string, logger *log.Logger, onAlert func(Alert)) (*Engine, error) {
	env, err := celEnvironment()
	if err != nil {
		return nil, fmt.Errorf("create CEL env: %w", err)
	}

	e := &Engine{
		env:     env,
		logger:  logger,
		onAlert: onAlert,
	}

	dirs := []string{rulesDir}
	if customDir != "" {
		dirs = append(dirs, customDir)
	}

	e.loader = NewLoader(dirs, logger, e.compile)

	// Initial load.
	if err := e.loader.LoadAll(); err != nil {
		return nil, fmt.Errorf("initial rule load: %w", err)
	}

	// Start hot-reload watcher.
	if err := e.loader.Watch(); err != nil {
		logger.Printf("warning: hot-reload disabled: %v", err)
	}

	return e, nil
}

// compile is called by the Loader whenever rules are (re)loaded. It compiles
// all rules into CEL programs and atomically swaps the rule set.
func (e *Engine) compile(macros map[string]string, lists map[string][]string, rules []Rule) {
	var compiled []CompiledRule
	for _, r := range rules {
		// Skip disabled rules.
		if r.Enabled != nil && !*r.Enabled {
			continue
		}

		// Expand macros and lists in the condition.
		condition := r.Condition
		condition = expandMacros(condition, macros)
		condition = expandLists(condition, lists)

		// Translate Falco-style operators to CEL syntax.
		condition = translateFalcoOps(condition)

		// Coerce bare integer literals to uint() for uint-typed fields.
		condition = coerceIntToUint(condition)

		// Compile.
		ast, issues := e.env.Compile(condition)
		if issues != nil && issues.Err() != nil {
			e.logger.Printf("warning: rule %q failed to compile: %v (condition: %s)", r.Name, issues.Err(), condition)
			continue
		}

		prg, err := e.env.Program(ast)
		if err != nil {
			e.logger.Printf("warning: rule %q failed to program: %v", r.Name, err)
			continue
		}

		compiled = append(compiled, CompiledRule{Rule: r, Program: prg})
	}

	e.mu.Lock()
	e.rules = compiled
	e.mu.Unlock()

	e.logger.Printf("rules engine: %d/%d rules compiled successfully", len(compiled), len(rules))
}

// EventVars holds the CEL variable bindings for an event. This is populated
// by the caller (the eBPF collector) from the EnrichedEvent.
type EventVars struct {
	// Event type
	EvtType   string
	EvtSource string

	// Process
	ProcName      string
	ProcCmdline   string
	ProcExePath   string
	ProcPID       uint64
	ProcPPID      uint64
	ProcUID       uint64
	ProcGID       uint64
	ProcAncestors []string
	ProcPName     string // parent name (first ancestor)

	// Container
	ContainerID    string
	ContainerName  string
	ContainerImage string

	// Kubernetes
	K8sNS     string
	K8sPod    string
	K8sLabels map[string]string

	// Network
	NetSrcIP     string
	NetDstIP     string
	NetSrcPort   uint64
	NetDstPort   uint64
	NetProtocol  string
	NetDirection string

	// File
	FilePath      string
	FileFlags     uint64
	FileMode      uint64
	FileDirectory string
	FileName      string

	// Syscall
	SyscallNr   uint64
	SyscallName string
	SyscallArgs []uint64

	// Credential
	CredOldUID uint64
	CredNewUID uint64
	CredOldGID uint64
	CredNewGID uint64

	// TLS
	TLSDataLen uint64

	// Timestamp
	TimestampNs int64
}

// Evaluate runs the event against all compiled rules and fires onAlert for
// each match. It returns the number of rules that matched.
func (e *Engine) Evaluate(vars EventVars) int {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	if len(rules) == 0 {
		return 0
	}

	activation := vars.toActivation()
	matches := 0

	for _, cr := range rules {
		// Check source filter.
		if cr.Rule.Source != "" && cr.Rule.Source != vars.EvtSource {
			continue
		}

		// Check scope (namespace/container/image scoping).
		if !e.matchesScope(cr.Rule.Scope, vars) {
			continue
		}

		out, _, err := cr.Program.Eval(activation)
		if err != nil {
			// Evaluation errors are expected when a field is empty/irrelevant
			// for the event type. Silently skip.
			continue
		}

		matched, ok := out.Value().(bool)
		if !ok || !matched {
			continue
		}

		// Check exceptions (allowlist).
		if e.matchesException(cr.Rule.Exceptions, vars) {
			continue
		}

		matches++

		if e.onAlert != nil {
			alert := Alert{
				RuleName:  cr.Rule.Name,
				Output:    e.renderOutput(cr.Rule.Output, vars),
				Priority:  ParsePriority(cr.Rule.Priority),
				Tags:      cr.Rule.Tags,
				Source:    vars.EvtSource,
				Fields:    cr.Rule.Metadata,
				Timestamp: vars.TimestampNs,
			}
			e.onAlert(alert)
		}
	}

	return matches
}

// toActivation converts EventVars to a CEL activation map.
func (v EventVars) toActivation() map[string]interface{} {
	ancestors := make([]interface{}, len(v.ProcAncestors))
	for i, a := range v.ProcAncestors {
		ancestors[i] = a
	}

	syscallArgs := make([]interface{}, len(v.SyscallArgs))
	for i, a := range v.SyscallArgs {
		syscallArgs[i] = a
	}

	labels := make(map[string]interface{}, len(v.K8sLabels))
	for k, val := range v.K8sLabels {
		labels[k] = val
	}

	return map[string]interface{}{
		"evt.type":        v.EvtType,
		"evt.source":      v.EvtSource,
		"proc.name":       v.ProcName,
		"proc.cmdline":    v.ProcCmdline,
		"proc.exepath":    v.ProcExePath,
		"proc.pid":        v.ProcPID,
		"proc.ppid":       v.ProcPPID,
		"proc.uid":        v.ProcUID,
		"proc.gid":        v.ProcGID,
		"proc.ancestors":  ancestors,
		"proc.pname":      v.ProcPName,
		"container.id":    v.ContainerID,
		"container.name":  v.ContainerName,
		"container.image": v.ContainerImage,
		"k8s.ns":          v.K8sNS,
		"k8s.pod":         v.K8sPod,
		"k8s.labels":      labels,
		"net.src_ip":      v.NetSrcIP,
		"net.dst_ip":      v.NetDstIP,
		"net.src_port":    v.NetSrcPort,
		"net.dst_port":    v.NetDstPort,
		"net.protocol":    v.NetProtocol,
		"net.direction":   v.NetDirection,
		"file.path":       v.FilePath,
		"file.flags":      v.FileFlags,
		"file.mode":       v.FileMode,
		"file.directory":  v.FileDirectory,
		"file.name":       v.FileName,
		"syscall.nr":      v.SyscallNr,
		"syscall.name":    v.SyscallName,
		"syscall.args":    syscallArgs,
		"cred.old_uid":    v.CredOldUID,
		"cred.new_uid":    v.CredNewUID,
		"cred.old_gid":    v.CredOldGID,
		"cred.new_gid":    v.CredNewGID,
		"tls.data_len":    v.TLSDataLen,
	}
}

// matchesScope checks if the event falls within the rule's scope.
func (e *Engine) matchesScope(scope *RuleScope, vars EventVars) bool {
	if scope == nil {
		return true
	}

	if len(scope.Namespaces) > 0 {
		found := false
		for _, ns := range scope.Namespaces {
			if ns == vars.K8sNS {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(scope.Containers) > 0 {
		found := false
		for _, c := range scope.Containers {
			if c == vars.ContainerName {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(scope.Images) > 0 {
		found := false
		for _, img := range scope.Images {
			if matchGlob(vars.ContainerImage, img) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// matchesException returns true if the event matches any of the rule's exceptions.
func (e *Engine) matchesException(exceptions []RuleException, vars EventVars) bool {
	for _, exc := range exceptions {
		for _, valueRow := range exc.Values {
			if len(valueRow) != len(exc.Fields) {
				continue
			}
			allMatch := true
			for i, field := range exc.Fields {
				comp := "="
				if i < len(exc.Comps) {
					comp = exc.Comps[i]
				}
				fieldVal := vars.getField(field)
				if !matchComp(fieldVal, comp, valueRow[i]) {
					allMatch = false
					break
				}
			}
			if allMatch {
				return true
			}
		}
	}
	return false
}

// getField returns the string value of a named field from EventVars.
func (v EventVars) getField(name string) string {
	switch name {
	case "evt.type":
		return v.EvtType
	case "proc.name":
		return v.ProcName
	case "proc.cmdline":
		return v.ProcCmdline
	case "proc.exepath":
		return v.ProcExePath
	case "proc.pname":
		return v.ProcPName
	case "container.id":
		return v.ContainerID
	case "container.name":
		return v.ContainerName
	case "container.image":
		return v.ContainerImage
	case "k8s.ns":
		return v.K8sNS
	case "k8s.pod":
		return v.K8sPod
	case "file.path":
		return v.FilePath
	case "net.dst_ip":
		return v.NetDstIP
	case "net.src_ip":
		return v.NetSrcIP
	case "net.protocol":
		return v.NetProtocol
	case "net.direction":
		return v.NetDirection
	case "syscall.name":
		return v.SyscallName
	default:
		return ""
	}
}

// matchComp performs a comparison.
func matchComp(fieldVal, comp, expected string) bool {
	switch comp {
	case "=", "==":
		return fieldVal == expected
	case "contains":
		return strings.Contains(fieldVal, expected)
	case "startswith":
		return strings.HasPrefix(fieldVal, expected)
	case "endswith":
		return strings.HasSuffix(fieldVal, expected)
	case "glob":
		return matchGlob(fieldVal, expected)
	default:
		return fieldVal == expected
	}
}

// renderOutput replaces %field% placeholders in the output template.
func (e *Engine) renderOutput(tmpl string, vars EventVars) string {
	replacements := map[string]string{
		"%evt.type%":        vars.EvtType,
		"%proc.name%":       vars.ProcName,
		"%proc.cmdline%":    vars.ProcCmdline,
		"%proc.exepath%":    vars.ProcExePath,
		"%proc.pid%":        fmt.Sprintf("%d", vars.ProcPID),
		"%proc.ppid%":       fmt.Sprintf("%d", vars.ProcPPID),
		"%proc.uid%":        fmt.Sprintf("%d", vars.ProcUID),
		"%proc.pname%":      vars.ProcPName,
		"%container.id%":    vars.ContainerID,
		"%container.name%":  vars.ContainerName,
		"%container.image%": vars.ContainerImage,
		"%k8s.ns%":          vars.K8sNS,
		"%k8s.pod%":         vars.K8sPod,
		"%file.path%":       vars.FilePath,
		"%net.dst_ip%":      vars.NetDstIP,
		"%net.dst_port%":    fmt.Sprintf("%d", vars.NetDstPort),
		"%net.src_ip%":      vars.NetSrcIP,
		"%net.src_port%":    fmt.Sprintf("%d", vars.NetSrcPort),
		"%net.protocol%":    vars.NetProtocol,
		"%net.direction%":   vars.NetDirection,
		"%syscall.name%":    vars.SyscallName,
		"%syscall.nr%":      fmt.Sprintf("%d", vars.SyscallNr),
	}

	result := tmpl
	for placeholder, value := range replacements {
		result = strings.ReplaceAll(result, placeholder, value)
	}
	return result
}

// RuleCount returns the number of currently compiled rules.
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// RuleNames returns the names of all currently compiled rules.
func (e *Engine) RuleNames() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	names := make([]string, len(e.rules))
	for i, r := range e.rules {
		names[i] = r.Rule.Name
	}
	return names
}

// Close stops the hot-reload watcher.
func (e *Engine) Close() error {
	if e.loader != nil {
		return e.loader.Close()
	}
	return nil
}

// Stats returns engine statistics.
func (e *Engine) Stats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]interface{}{
		"compiled_rules": len(e.rules),
		"rule_names":     e.RuleNames(),
		"dirs":           e.loader.dirs,
		"timestamp":      time.Now().Unix(),
	}
}

// EnrichedEventToVars converts an EnrichedEvent-like set of fields into EventVars.
// This is a helper for the ebpf-collector's main package to bridge the gap.
// Since we can't import the main package (circular), the caller populates EventVars directly.
// This function exists as documentation of the expected field mapping.
func EnrichedEventToVars() string {
	return `
EventVars{
	EvtType:        enriched.EventType,
	EvtSource:      enriched.Source,
	ProcName:       enriched.ProcName,
	ProcCmdline:    enriched.ProcCmdline,
	ProcExePath:    enriched.ProcExePath,
	ProcPID:        uint64(enriched.ProcPID),
	ProcPPID:       uint64(enriched.ProcPPID),
	ProcUID:        uint64(enriched.ProcUID),
	ProcGID:        uint64(enriched.ProcGID),
	ProcAncestors:  enriched.ProcAncestors,
	ProcPName:      parentName,
	ContainerID:    enriched.ContainerID,
	ContainerName:  enriched.ContainerName,
	ContainerImage: enriched.ContainerImage,
	K8sNS:          enriched.K8sNamespace,
	K8sPod:         enriched.K8sPod,
	K8sLabels:      enriched.K8sLabels,
	...
}
`
}

// DefaultRulesDir returns the default path for built-in rules relative to
// the eBPF asset directory.
func DefaultRulesDir(ebpfDir string) string {
	return filepath.Join(ebpfDir, "..", "rules", "builtin")
}

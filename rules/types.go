package rules

// Priority maps to Falco-compatible priority levels.
type Priority int

const (
	PriorityDebug         Priority = iota // 0
	PriorityInformational                 // 1
	PriorityNotice                        // 2
	PriorityWarning                       // 3
	PriorityError                         // 4
	PriorityCritical                      // 5
	PriorityAlert                         // 6
	PriorityEmergency                     // 7
)

func (p Priority) String() string {
	switch p {
	case PriorityDebug:
		return "DEBUG"
	case PriorityInformational:
		return "INFORMATIONAL"
	case PriorityNotice:
		return "NOTICE"
	case PriorityWarning:
		return "WARNING"
	case PriorityError:
		return "ERROR"
	case PriorityCritical:
		return "CRITICAL"
	case PriorityAlert:
		return "ALERT"
	case PriorityEmergency:
		return "EMERGENCY"
	default:
		return "UNKNOWN"
	}
}

// ParsePriority converts a string to a Priority. Case-insensitive.
func ParsePriority(s string) Priority {
	switch s {
	case "DEBUG", "debug":
		return PriorityDebug
	case "INFORMATIONAL", "informational", "INFO", "info":
		return PriorityInformational
	case "NOTICE", "notice":
		return PriorityNotice
	case "WARNING", "warning", "WARN", "warn":
		return PriorityWarning
	case "ERROR", "error":
		return PriorityError
	case "CRITICAL", "critical":
		return PriorityCritical
	case "ALERT", "alert":
		return PriorityAlert
	case "EMERGENCY", "emergency":
		return PriorityEmergency
	default:
		return PriorityWarning
	}
}

// RuleFile represents a YAML file containing rules, macros, and lists.
type RuleFile struct {
	Entries []RuleEntry `yaml:"-"`
}

// RuleEntry is a union type: exactly one of Rule, Macro, or List is populated.
type RuleEntry struct {
	Rule  *Rule  `yaml:"-"`
	Macro *Macro `yaml:"-"`
	List  *List  `yaml:"-"`
}

// Rule defines a detection rule.
type Rule struct {
	Name       string            `yaml:"rule"`
	Desc       string            `yaml:"desc,omitempty"`
	Condition  string            `yaml:"condition"`
	Output     string            `yaml:"output"`
	Priority   string            `yaml:"priority"`
	Enabled    *bool             `yaml:"enabled,omitempty"`
	Tags       []string          `yaml:"tags,omitempty"`
	Source     string            `yaml:"source,omitempty"` // "ebpf" or "k8s_audit", default "ebpf"
	Exceptions []RuleException   `yaml:"exceptions,omitempty"`
	Scope      *RuleScope        `yaml:"scope,omitempty"`
	Metadata   map[string]string `yaml:"metadata,omitempty"`
}

// Macro defines a reusable boolean expression fragment.
type Macro struct {
	Name      string `yaml:"macro"`
	Condition string `yaml:"condition"`
}

// List defines a reusable set of values.
type List struct {
	Name  string   `yaml:"list"`
	Items []string `yaml:"items"`
}

// RuleException defines an exception (allowlist) for a rule.
type RuleException struct {
	Name   string     `yaml:"name"`
	Fields []string   `yaml:"fields"`
	Comps  []string   `yaml:"comps,omitempty"` // "=", "contains", "startswith", "endswith", "regex"
	Values [][]string `yaml:"values"`
}

// RuleScope limits a rule to specific namespaces, containers, or images.
type RuleScope struct {
	Namespaces []string `yaml:"namespaces,omitempty"`
	Containers []string `yaml:"containers,omitempty"`
	Images     []string `yaml:"images,omitempty"`
}

// Alert is the output produced when a compiled rule matches an event.
type Alert struct {
	RuleName   string            `json:"rule"`
	Output     string            `json:"output"`
	Priority   Priority          `json:"priority"`
	Tags       []string          `json:"tags,omitempty"`
	Source     string            `json:"source"`
	Fields     map[string]string `json:"fields,omitempty"`
	Timestamp  int64             `json:"timestamp_ns"`
}

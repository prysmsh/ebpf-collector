package rules

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// celEnvironment builds the CEL environment with all event field declarations
// and custom functions available for rule evaluation.
func celEnvironment() (*cel.Env, error) {
	return cel.NewEnv(
		// ---- Event type ----
		cel.Variable("evt.type", cel.StringType),
		cel.Variable("evt.source", cel.StringType),

		// ---- Process fields ----
		cel.Variable("proc.name", cel.StringType),
		cel.Variable("proc.cmdline", cel.StringType),
		cel.Variable("proc.exepath", cel.StringType),
		cel.Variable("proc.pid", cel.UintType),
		cel.Variable("proc.ppid", cel.UintType),
		cel.Variable("proc.uid", cel.UintType),
		cel.Variable("proc.gid", cel.UintType),
		cel.Variable("proc.ancestors", cel.ListType(cel.StringType)),

		// Ancestor access helpers: proc.pname = parent name
		cel.Variable("proc.pname", cel.StringType),
		// proc.aname_2, proc.aname_3, etc. — not needed, use proc.ancestors[N]

		// ---- Container fields ----
		cel.Variable("container.id", cel.StringType),
		cel.Variable("container.name", cel.StringType),
		cel.Variable("container.image", cel.StringType),

		// ---- Kubernetes fields ----
		cel.Variable("k8s.ns", cel.StringType),
		cel.Variable("k8s.pod", cel.StringType),
		cel.Variable("k8s.labels", cel.MapType(cel.StringType, cel.StringType)),

		// ---- Network fields ----
		cel.Variable("net.src_ip", cel.StringType),
		cel.Variable("net.dst_ip", cel.StringType),
		cel.Variable("net.src_port", cel.UintType),
		cel.Variable("net.dst_port", cel.UintType),
		cel.Variable("net.protocol", cel.StringType),
		cel.Variable("net.direction", cel.StringType),

		// ---- File fields ----
		cel.Variable("file.path", cel.StringType),
		cel.Variable("file.flags", cel.UintType),
		cel.Variable("file.mode", cel.UintType),
		cel.Variable("file.directory", cel.StringType),
		cel.Variable("file.name", cel.StringType),

		// ---- Syscall fields ----
		cel.Variable("syscall.nr", cel.UintType),
		cel.Variable("syscall.name", cel.StringType),
		cel.Variable("syscall.args", cel.ListType(cel.UintType)),

		// ---- Credential change fields ----
		cel.Variable("cred.old_uid", cel.UintType),
		cel.Variable("cred.new_uid", cel.UintType),
		cel.Variable("cred.old_gid", cel.UintType),
		cel.Variable("cred.new_gid", cel.UintType),

		// ---- TLS fields ----
		cel.Variable("tls.data_len", cel.UintType),

		// ---- Custom functions ----

		// in_list(value, list_name) — resolved at compile time, replaced with `value in [...]`
		// We use a simpler approach: lists are inlined into the CEL expression
		// before compilation, so no custom function is needed.

		// contains(haystack, needle) — string contains
		// CEL has built-in string.contains(s), so no custom function needed.

		// startswith / endswith — CEL has built-in string.startsWith/endsWith.

		// glob(s, pattern) — simple glob matching (*, ?)
		cel.Function("glob",
			cel.Overload("glob_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(globMatch),
			),
		),

		// pmatch(s, prefix_list) — true if s starts with any of the prefixes
		cel.Function("pmatch",
			cel.Overload("pmatch_string_list",
				[]*cel.Type{cel.StringType, cel.ListType(cel.StringType)},
				cel.BoolType,
				cel.BinaryBinding(prefixMatch),
			),
		),
	)
}

// globMatch implements simple glob matching (* and ?).
func globMatch(lhs, rhs ref.Val) ref.Val {
	s, ok1 := lhs.Value().(string)
	pattern, ok2 := rhs.Value().(string)
	if !ok1 || !ok2 {
		return types.Bool(false)
	}
	return types.Bool(matchGlob(s, pattern))
}

// matchGlob performs basic glob matching with * (any chars) and ? (single char).
func matchGlob(s, pattern string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			// Skip consecutive stars
			for len(pattern) > 0 && pattern[0] == '*' {
				pattern = pattern[1:]
			}
			if len(pattern) == 0 {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if matchGlob(s[i:], pattern) {
					return true
				}
			}
			return false
		case '?':
			if len(s) == 0 {
				return false
			}
			s = s[1:]
			pattern = pattern[1:]
		default:
			if len(s) == 0 || s[0] != pattern[0] {
				return false
			}
			s = s[1:]
			pattern = pattern[1:]
		}
	}
	return len(s) == 0
}

// prefixMatch returns true if s starts with any of the given prefixes.
func prefixMatch(lhs, rhs ref.Val) ref.Val {
	s, ok := lhs.Value().(string)
	if !ok {
		return types.Bool(false)
	}
	list, ok := rhs.(ref.Val)
	if !ok {
		return types.Bool(false)
	}
	iter, ok := list.Value().([]ref.Val)
	if ok {
		for _, v := range iter {
			if prefix, ok := v.Value().(string); ok {
				if strings.HasPrefix(s, prefix) {
					return types.Bool(true)
				}
			}
		}
	}
	// Also handle native string slice
	if strList, ok := list.Value().([]string); ok {
		for _, prefix := range strList {
			if strings.HasPrefix(s, prefix) {
				return types.Bool(true)
			}
		}
	}
	return types.Bool(false)
}

// expandMacros replaces macro references in a condition string. Each macro
// reference "macro_name" is replaced with "(macro_condition)".
func expandMacros(condition string, macros map[string]string) string {
	// Iterate multiple times to handle nested macros (max 10 passes).
	for i := 0; i < 10; i++ {
		expanded := condition
		for name, body := range macros {
			expanded = strings.ReplaceAll(expanded, name, "("+body+")")
		}
		if expanded == condition {
			break
		}
		condition = expanded
	}
	return condition
}

// expandLists replaces list references of the form "in (list_name)" with
// the actual list values "in ['item1', 'item2', ...]".
func expandLists(condition string, lists map[string][]string) string {
	for name, items := range lists {
		// Build a CEL list literal: ['item1', 'item2']
		quoted := make([]string, len(items))
		for i, item := range items {
			quoted[i] = fmt.Sprintf("'%s'", strings.ReplaceAll(item, "'", "\\'"))
		}
		replacement := "[" + strings.Join(quoted, ", ") + "]"

		// Replace "in (list_name)" → "in [items]"
		condition = strings.ReplaceAll(condition, "in ("+name+")", "in "+replacement)
		// Also replace bare list references used with `in` operator
		condition = strings.ReplaceAll(condition, "("+name+")", replacement)
	}
	return condition
}

// uintFields is the set of CEL variable names that have uint type.
// When a rule compares one of these against a bare integer literal the
// translator must wrap the literal with uint() so CEL type-checking passes.
var uintFields = map[string]bool{
	"proc.pid":      true,
	"proc.ppid":     true,
	"proc.uid":      true,
	"proc.gid":      true,
	"net.src_port":  true,
	"net.dst_port":  true,
	"file.flags":    true,
	"file.mode":     true,
	"syscall.nr":    true,
	"cred.old_uid":  true,
	"cred.new_uid":  true,
	"cred.old_gid":  true,
	"cred.new_gid":  true,
	"tls.data_len":  true,
}

// coerceIntToUint wraps bare integer literals with uint() when they appear
// next to a uint-typed field in comparisons (==, !=, >, <, >=, <=, in [...]).
func coerceIntToUint(condition string) string {
	result := condition

	// Handle "field op N" patterns where field is uint and N is a bare integer.
	for field := range uintFields {
		// Patterns: "field == N", "field != N", "field > N", "field < N", "field >= N", "field <= N"
		for _, op := range []string{" == ", " != ", " > ", " < ", " >= ", " <= "} {
			prefix := field + op
			result = wrapIntLiterals(result, prefix)
		}

		// Handle "field in [N, M, ...]" — wrap each integer in the list.
		result = wrapInListInts(result, field+" in [")
	}

	return result
}

// wrapIntLiterals finds all occurrences of prefix+integer and wraps the integer
// with uint().
func wrapIntLiterals(s, prefix string) string {
	searchFrom := 0
	for {
		idx := strings.Index(s[searchFrom:], prefix)
		if idx < 0 {
			break
		}
		idx += searchFrom
		afterPrefix := idx + len(prefix)
		if afterPrefix >= len(s) {
			break
		}

		rest := s[afterPrefix:]
		if len(rest) == 0 || (rest[0] < '0' || rest[0] > '9') {
			// Not a bare integer literal; skip past this occurrence.
			searchFrom = afterPrefix
			continue
		}

		// Find end of integer
		end := 0
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}

		// Check if already wrapped (next char after digits is ')').
		if end < len(rest) && rest[end] == ')' {
			searchFrom = afterPrefix + end + 1
			continue
		}

		intLit := rest[:end]
		replacement := "uint(" + intLit + ")"
		s = s[:afterPrefix] + replacement + rest[end:]
		searchFrom = afterPrefix + len(replacement)
	}
	return s
}

// wrapInListInts handles "field in [1, 2, 3]" → "field in [uint(1), uint(2), uint(3)]".
func wrapInListInts(s, prefix string) string {
	for {
		idx := strings.Index(s, prefix)
		if idx < 0 {
			break
		}
		listStart := idx + len(prefix)
		// Find the closing bracket.
		bracketEnd := strings.IndexByte(s[listStart:], ']')
		if bracketEnd < 0 {
			break
		}
		bracketEnd += listStart

		listContent := s[listStart:bracketEnd]
		// Split by comma, wrap any bare integers with uint().
		items := strings.Split(listContent, ",")
		for i, item := range items {
			item = strings.TrimSpace(item)
			// Check if it's a bare integer (not already wrapped).
			if len(item) > 0 && item[0] >= '0' && item[0] <= '9' && !strings.Contains(item, "uint(") {
				items[i] = " uint(" + item + ")"
			} else {
				items[i] = " " + item
			}
		}
		newList := strings.Join(items, ",")
		s = s[:listStart] + newList + s[bracketEnd:]
		// Advance past the replacement to avoid infinite loop.
		break
	}
	return s
}

// translateFalcoOps translates Falco-style operators to CEL equivalents.
func translateFalcoOps(condition string) string {
	// "= " → "== " (but not "!=" or ">=", "<=")
	// We do a targeted replacement: standalone "=" that is not part of ==, !=, >=, <=
	result := condition

	// Replace " = " with " == " (Falco uses single = for equality)
	result = strings.ReplaceAll(result, " = ", " == ")

	// "and" → "&&", "or" → "||", "not " → "!"
	result = replaceWord(result, "and", "&&")
	result = replaceWord(result, "or", "||")
	result = replaceWord(result, "not", "!")

	// "contains" → .contains() — handled specially: "field contains 'value'" → "field.contains('value')"
	result = translateContains(result)

	// "startswith" → .startsWith()
	result = translateStringMethod(result, "startswith", "startsWith")

	// "endswith" → .endsWith()
	result = translateStringMethod(result, "endswith", "endsWith")

	return result
}

// replaceWord replaces whole-word occurrences of old with new.
func replaceWord(s, old, replacement string) string {
	// Simple approach: split by whitespace-bounded word
	words := strings.Fields(s)
	for i, w := range words {
		if w == old {
			words[i] = replacement
		}
	}
	return strings.Join(words, " ")
}

// translateContains converts "field contains 'value'" to "field.contains('value')".
func translateContains(s string) string {
	for {
		idx := findWord(s, "contains")
		if idx < 0 {
			break
		}
		// Find the field before "contains" and the value after
		before := strings.TrimRight(s[:idx], " ")
		after := strings.TrimLeft(s[idx+len("contains"):], " ")

		// Get the last token before "contains" as the field
		lastSpace := strings.LastIndexByte(before, ' ')
		var field, prefix string
		if lastSpace >= 0 {
			prefix = before[:lastSpace+1]
			field = before[lastSpace+1:]
		} else {
			prefix = ""
			field = before
		}

		// Get the value token after "contains"
		var value, suffix string
		nextSpace := findEndOfToken(after)
		if nextSpace >= 0 {
			value = after[:nextSpace]
			suffix = after[nextSpace:]
		} else {
			value = after
			suffix = ""
		}

		s = prefix + field + ".contains(" + value + ")" + suffix
	}
	return s
}

// translateStringMethod converts "field method 'value'" to "field.celMethod('value')".
func translateStringMethod(s, falcoMethod, celMethod string) string {
	for {
		idx := findWord(s, falcoMethod)
		if idx < 0 {
			break
		}
		before := strings.TrimRight(s[:idx], " ")
		after := strings.TrimLeft(s[idx+len(falcoMethod):], " ")

		lastSpace := strings.LastIndexByte(before, ' ')
		var field, prefix string
		if lastSpace >= 0 {
			prefix = before[:lastSpace+1]
			field = before[lastSpace+1:]
		} else {
			prefix = ""
			field = before
		}

		var value, suffix string
		nextSpace := findEndOfToken(after)
		if nextSpace >= 0 {
			value = after[:nextSpace]
			suffix = after[nextSpace:]
		} else {
			value = after
			suffix = ""
		}

		s = prefix + field + "." + celMethod + "(" + value + ")" + suffix
	}
	return s
}

// findWord returns the index of a whole-word occurrence of word in s, or -1.
func findWord(s, word string) int {
	idx := 0
	for {
		pos := strings.Index(s[idx:], word)
		if pos < 0 {
			return -1
		}
		absPos := idx + pos
		// Check word boundaries
		before := absPos == 0 || s[absPos-1] == ' ' || s[absPos-1] == '('
		after := absPos+len(word) >= len(s) || s[absPos+len(word)] == ' ' || s[absPos+len(word)] == ')'
		if before && after {
			return absPos
		}
		idx = absPos + len(word)
	}
}

// findEndOfToken returns the end index of the next token (handles quoted strings).
func findEndOfToken(s string) int {
	if len(s) == 0 {
		return -1
	}
	if s[0] == '\'' {
		// Find closing quote
		end := strings.IndexByte(s[1:], '\'')
		if end >= 0 {
			return end + 2
		}
		return -1
	}
	if s[0] == '"' {
		end := strings.IndexByte(s[1:], '"')
		if end >= 0 {
			return end + 2
		}
		return -1
	}
	// Find next space or paren
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == ')' {
			return i
		}
	}
	return -1
}

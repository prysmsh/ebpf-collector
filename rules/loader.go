package rules

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// Loader reads YAML rule files from one or more directories and watches for
// changes. On each load (or reload) it calls the supplied callback with the
// complete set of parsed entries so the engine can recompile atomically.
type Loader struct {
	dirs     []string
	logger   *log.Logger
	onChange func(macros map[string]string, lists map[string][]string, rules []Rule)

	mu      sync.Mutex
	watcher *fsnotify.Watcher
}

// NewLoader creates a Loader that watches the given directories.
func NewLoader(dirs []string, logger *log.Logger, onChange func(map[string]string, map[string][]string, []Rule)) *Loader {
	return &Loader{
		dirs:     dirs,
		logger:   logger,
		onChange: onChange,
	}
}

// LoadAll reads all YAML files from the configured directories, parses them
// into macros, lists, and rules, and invokes the onChange callback.
func (l *Loader) LoadAll() error {
	macros := make(map[string]string)
	lists := make(map[string][]string)
	var rules []Rule

	for _, dir := range l.dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				l.logger.Printf("rules directory %s does not exist, skipping", dir)
				continue
			}
			return fmt.Errorf("read dir %s: %w", dir, err)
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if ext != ".yaml" && ext != ".yml" {
				continue
			}

			path := filepath.Join(dir, entry.Name())
			m, li, r, err := l.parseFile(path)
			if err != nil {
				l.logger.Printf("warning: failed to parse %s: %v", path, err)
				continue
			}

			for k, v := range m {
				macros[k] = v
			}
			for k, v := range li {
				lists[k] = v
			}
			rules = append(rules, r...)
		}
	}

	l.logger.Printf("loaded %d macros, %d lists, %d rules from %d directories",
		len(macros), len(lists), len(rules), len(l.dirs))

	if l.onChange != nil {
		l.onChange(macros, lists, rules)
	}
	return nil
}

// parseFile reads a single YAML file containing a sequence of rule/macro/list
// entries in the Falco YAML format.
func (l *Loader) parseFile(path string) (map[string]string, map[string][]string, []Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, err
	}

	// The file is a YAML sequence of maps. Each map has a distinguishing key:
	//   - "rule" → Rule
	//   - "macro" → Macro
	//   - "list" → List
	var raw []map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, nil, nil, fmt.Errorf("yaml parse: %w", err)
	}

	macros := make(map[string]string)
	lists := make(map[string][]string)
	var rules []Rule

	for _, entry := range raw {
		if _, ok := entry["macro"]; ok {
			m, err := parseYAMLMacro(entry)
			if err != nil {
				l.logger.Printf("warning: skip macro in %s: %v", path, err)
				continue
			}
			macros[m.Name] = m.Condition
		} else if _, ok := entry["list"]; ok {
			li, err := parseYAMLList(entry)
			if err != nil {
				l.logger.Printf("warning: skip list in %s: %v", path, err)
				continue
			}
			lists[li.Name] = li.Items
		} else if _, ok := entry["rule"]; ok {
			r, err := parseYAMLRule(entry)
			if err != nil {
				l.logger.Printf("warning: skip rule in %s: %v", path, err)
				continue
			}
			rules = append(rules, r)
		}
	}

	return macros, lists, rules, nil
}

func parseYAMLMacro(m map[string]interface{}) (Macro, error) {
	name, _ := m["macro"].(string)
	condition, _ := m["condition"].(string)
	if name == "" || condition == "" {
		return Macro{}, fmt.Errorf("macro missing name or condition")
	}
	return Macro{Name: name, Condition: condition}, nil
}

func parseYAMLList(m map[string]interface{}) (List, error) {
	name, _ := m["list"].(string)
	if name == "" {
		return List{}, fmt.Errorf("list missing name")
	}
	rawItems, _ := m["items"].([]interface{})
	items := make([]string, 0, len(rawItems))
	for _, item := range rawItems {
		items = append(items, fmt.Sprintf("%v", item))
	}
	return List{Name: name, Items: items}, nil
}

func parseYAMLRule(m map[string]interface{}) (Rule, error) {
	name, _ := m["rule"].(string)
	condition, _ := m["condition"].(string)
	if name == "" || condition == "" {
		return Rule{}, fmt.Errorf("rule missing name or condition")
	}

	r := Rule{
		Name:      name,
		Condition: condition,
	}

	if v, ok := m["desc"].(string); ok {
		r.Desc = v
	}
	if v, ok := m["output"].(string); ok {
		r.Output = v
	}
	if v, ok := m["priority"].(string); ok {
		r.Priority = v
	}
	if v, ok := m["source"].(string); ok {
		r.Source = v
	}
	if v, ok := m["enabled"].(bool); ok {
		r.Enabled = &v
	}
	if v, ok := m["tags"].([]interface{}); ok {
		for _, tag := range v {
			r.Tags = append(r.Tags, fmt.Sprintf("%v", tag))
		}
	}
	if v, ok := m["metadata"].(map[string]interface{}); ok {
		r.Metadata = make(map[string]string)
		for k, val := range v {
			r.Metadata[k] = fmt.Sprintf("%v", val)
		}
	}

	// Parse exceptions
	if v, ok := m["exceptions"].([]interface{}); ok {
		for _, exc := range v {
			excMap, ok := exc.(map[string]interface{})
			if !ok {
				continue
			}
			re := RuleException{}
			re.Name, _ = excMap["name"].(string)
			if fields, ok := excMap["fields"].([]interface{}); ok {
				for _, f := range fields {
					re.Fields = append(re.Fields, fmt.Sprintf("%v", f))
				}
			}
			if comps, ok := excMap["comps"].([]interface{}); ok {
				for _, c := range comps {
					re.Comps = append(re.Comps, fmt.Sprintf("%v", c))
				}
			}
			if values, ok := excMap["values"].([]interface{}); ok {
				for _, valRow := range values {
					if row, ok := valRow.([]interface{}); ok {
						var strRow []string
						for _, v := range row {
							strRow = append(strRow, fmt.Sprintf("%v", v))
						}
						re.Values = append(re.Values, strRow)
					}
				}
			}
			r.Exceptions = append(r.Exceptions, re)
		}
	}

	// Parse scope
	if v, ok := m["scope"].(map[string]interface{}); ok {
		scope := &RuleScope{}
		if ns, ok := v["namespaces"].([]interface{}); ok {
			for _, n := range ns {
				scope.Namespaces = append(scope.Namespaces, fmt.Sprintf("%v", n))
			}
		}
		if cs, ok := v["containers"].([]interface{}); ok {
			for _, c := range cs {
				scope.Containers = append(scope.Containers, fmt.Sprintf("%v", c))
			}
		}
		if imgs, ok := v["images"].([]interface{}); ok {
			for _, img := range imgs {
				scope.Images = append(scope.Images, fmt.Sprintf("%v", img))
			}
		}
		r.Scope = scope
	}

	return r, nil
}

// Watch starts watching rule directories for changes via fsnotify.
// On any create/write/remove of a .yaml file the rules are reloaded.
func (l *Loader) Watch() error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create watcher: %w", err)
	}

	for _, dir := range l.dirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		if err := w.Add(dir); err != nil {
			l.logger.Printf("warning: cannot watch %s: %v", dir, err)
		}
	}

	l.mu.Lock()
	l.watcher = w
	l.mu.Unlock()

	go func() {
		for {
			select {
			case event, ok := <-w.Events:
				if !ok {
					return
				}
				ext := strings.ToLower(filepath.Ext(event.Name))
				if ext != ".yaml" && ext != ".yml" {
					continue
				}
				if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) != 0 {
					l.logger.Printf("rules file changed: %s (%s), reloading all rules", event.Name, event.Op)
					if err := l.LoadAll(); err != nil {
						l.logger.Printf("error reloading rules: %v", err)
					}
				}
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				l.logger.Printf("fsnotify error: %v", err)
			}
		}
	}()

	return nil
}

// Close stops watching for changes.
func (l *Loader) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.watcher != nil {
		return l.watcher.Close()
	}
	return nil
}

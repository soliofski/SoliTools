package param

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

// JSONField is a parameter candidate found in a JSON document together with
// the object path that leads to it, including the key itself.
type JSONField struct {
	Path []string
}

// FromJSON returns parameter names worth probing from a JSON document.
//
// Only keys classified High or Medium are returned: a JSON API exposes plenty
// of fields (timestamps, counts, flags) that are not input parameters, and
// probing them would be noise. Objects are walked up to maxDepth levels, arrays
// are traversed without consuming depth, and the result is sorted so the output
// is deterministic even though Go map iteration is not.
func FromJSON(body []byte, maxDepth int) []string {
	fields := FromJSONFields(body, maxDepth)
	if len(fields) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(fields))
	names := make([]string, 0, len(fields))
	for _, field := range fields {
		if len(field.Path) == 0 {
			continue
		}
		name := field.Path[len(field.Path)-1]
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// FromJSONFields is FromJSON with paths, so a nested candidate can be probed
// with a nested body instead of a flattened key.
func FromJSONFields(body []byte, maxDepth int) []JSONField {
	if len(body) == 0 || maxDepth <= 0 {
		return nil
	}

	var root any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		return nil
	}

	fields := make([]JSONField, 0, 8)
	var walk func(value any, level int, path []string)
	walk = func(value any, level int, path []string) {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				next := append(append([]string{}, path...), key)
				if level < maxDepth && len(key) <= 40 {
					interest := Classify(key)
					if interest == High || interest == Medium {
						fields = append(fields, JSONField{Path: next})
					}
				}
				walk(child, level+1, next)
			}
		case []any:
			for _, child := range typed {
				walk(child, level, path)
			}
		}
	}
	walk(root, 0, nil)

	sort.SliceStable(fields, func(i, j int) bool {
		return strings.Join(fields[i].Path, "\x00") < strings.Join(fields[j].Path, "\x00")
	})
	return fields
}

// LooksJSON reports whether a response is JSON, by media type or by shape. The
// shape check catches APIs that mislabel themselves as text/plain, which is
// common enough to matter.
func LooksJSON(contentType string, body []byte) bool {
	media := strings.ToLower(strings.TrimSpace(contentType))
	if index := strings.IndexByte(media, ';'); index >= 0 {
		media = strings.TrimSpace(media[:index])
	}
	if media == "application/json" || strings.HasSuffix(media, "+json") {
		return true
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) < 2 {
		return false
	}
	return trimmed[0] == '{' || trimmed[0] == '['
}

package param

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

// FromJSON returns parameter names worth probing from a JSON document.
//
// Only keys classified High or Medium are returned: a JSON API exposes plenty
// of fields (timestamps, counts, flags) that are not input parameters, and
// probing them would be noise. Objects are walked up to maxDepth levels, arrays
// are traversed without consuming depth, and the result is sorted so the output
// is deterministic even though Go map iteration is not.
func FromJSON(body []byte, maxDepth int) []string {
	if len(body) == 0 || maxDepth <= 0 {
		return nil
	}

	var root any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		return nil
	}

	seen := make(map[string]struct{}, 8)
	var walk func(value any, level int)
	walk = func(value any, level int) {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				if level < maxDepth && len(key) <= 40 {
					interest := Classify(key)
					if interest == High || interest == Medium {
						seen[key] = struct{}{}
					}
				}
				walk(child, level+1)
			}
		case []any:
			for _, child := range typed {
				walk(child, level)
			}
		}
	}
	walk(root, 0)

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
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

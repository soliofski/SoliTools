package secret

import (
	"sort"
	"strings"
)

// span is a half-open byte range.
type span struct{ start, end int }

// commentIndex answers "is this offset inside a comment?" in log time.
//
// It exists so a credential that only appears in a comment, a docblock or an
// HTML comment can be filtered out. Detection is deliberately conservative:
// missing a comment keeps a finding (the safe direction), while a false
// positive here would hide a real credential.
type commentIndex struct {
	spans []span
}

func indexComments(text string, hashComments bool) commentIndex {
	spans := htmlCommentSpans(text)
	spans = append(spans, codeCommentSpans(text, hashComments)...)
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	return commentIndex{spans: spans}
}

func (c commentIndex) contains(offset int) bool {
	i := sort.Search(len(c.spans), func(i int) bool { return c.spans[i].end > offset })
	return i < len(c.spans) && c.spans[i].start <= offset
}

// htmlCommentSpans finds <!-- ... --> independently of code syntax, because
// apostrophes in prose would otherwise confuse the string tracker.
func htmlCommentSpans(text string) []span {
	var spans []span
	for i := 0; i < len(text); {
		start := strings.Index(text[i:], "<!--")
		if start < 0 {
			break
		}
		start += i
		closeAt := strings.Index(text[start+4:], "-->")
		if closeAt < 0 {
			spans = append(spans, span{start, len(text)})
			break
		}
		end := start + 4 + closeAt + 3
		spans = append(spans, span{start, end})
		i = end
	}
	return spans
}

// codeCommentSpans finds //, /* */ and optionally # comments, skipping string
// literals so a URL such as "https://host" is never mistaken for a comment.
func codeCommentSpans(text string, hashComments bool) []span {
	var spans []span
	lineStart := true

	for i := 0; i < len(text); {
		c := text[i]
		switch {
		case c == '\n':
			lineStart = true
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '/' && i+1 < len(text) && text[i+1] == '/':
			if i > 0 && text[i-1] == ':' {
				// Part of a URL scheme, not a comment.
				i += 2
				lineStart = false
				continue
			}
			end := len(text)
			if nl := strings.IndexByte(text[i:], '\n'); nl >= 0 {
				end = i + nl
			}
			spans = append(spans, span{i, end})
			i = end
		case c == '/' && i+1 < len(text) && text[i+1] == '*':
			end := len(text)
			if closeAt := strings.Index(text[i+2:], "*/"); closeAt >= 0 {
				end = i + 2 + closeAt + 2
			}
			spans = append(spans, span{i, end})
			i = end
		case hashComments && c == '#' && lineStart:
			end := len(text)
			if nl := strings.IndexByte(text[i:], '\n'); nl >= 0 {
				end = i + nl
			}
			spans = append(spans, span{i, end})
			i = end
		case c == '<' && strings.HasPrefix(text[i:], "<!--"):
			// Already covered by htmlCommentSpans; skip the block so its inner
			// quotes do not derail the string tracker.
			end := len(text)
			if closeAt := strings.Index(text[i+4:], "-->"); closeAt >= 0 {
				end = i + 4 + closeAt + 3
			}
			i = end
			lineStart = false
		case c == '"' || c == '\'' || c == '`':
			i = skipString(text, i)
			lineStart = false
		default:
			lineStart = false
			i++
		}
	}
	return spans
}

// skipString returns the offset just past the string literal starting at i.
func skipString(text string, i int) int {
	quote := text[i]
	i++
	for i < len(text) {
		switch text[i] {
		case '\\':
			i += 2
		case quote:
			return i + 1
		case '\n':
			if quote != '`' {
				return i
			}
			i++
		default:
			i++
		}
	}
	return len(text)
}

// hashCommentSource reports whether a source conventionally uses '#' comments.
func hashCommentSource(source string) bool {
	lower := strings.ToLower(source)
	for _, marker := range []string{".env", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".conf", ".ini", ".cfg", ".toml", ".py", ".properties"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

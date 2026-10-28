package js

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func scriptURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url %q: %v", raw, err)
	}
	return parsed
}

func headerWith(name, value string) http.Header {
	header := make(http.Header)
	header.Set(name, value)
	return header
}

func TestSourceMapURLFromComments(t *testing.T) {
	cases := []struct {
		name    string
		source  string
		headers http.Header
		want    string
	}{
		{
			name:   "line comment relative",
			source: "var a=1;\n//# sourceMappingURL=app.js.map\n",
			want:   "https://target.test/static/app.js.map",
		},
		{
			name:   "block comment",
			source: "var a=1;\n/*# sourceMappingURL=/maps/app.map */\n",
			want:   "https://target.test/maps/app.map",
		},
		{
			name:    "header wins",
			source:  "var a=1;",
			headers: headerWith("SourceMap", "/from-header.map"),
			want:    "https://target.test/from-header.map",
		},
		{
			name:    "x-sourcemap header",
			source:  "var a=1;",
			headers: headerWith("X-SourceMap", "nested/app.map"),
			want:    "https://target.test/static/nested/app.map",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := SourceMapURL([]byte(testCase.source), scriptURL(t, "https://target.test/static/app.js"), testCase.headers)
			if got != testCase.want {
				t.Fatalf("SourceMapURL = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestSourceMapURLRejectsOtherOrigins(t *testing.T) {
	cases := []string{
		"https://cdn.other.test/app.js.map",
		"http://target.test/app.js.map",       // scheme downgrade
		"https://target.test:8443/app.js.map", // port change
		"https://sub.target.test/app.js.map",  // different host
	}
	for _, candidate := range cases {
		source := []byte("//# sourceMappingURL=" + candidate)
		if got := SourceMapURL(source, scriptURL(t, "https://target.test/static/app.js"), nil); got != "" {
			t.Errorf("SourceMapURL(%q) = %q, want rejected", candidate, got)
		}
	}
}

func TestSourceMapURLIgnoresMentionInCode(t *testing.T) {
	source := []byte(`const hint = "sourceMappingURL=app.js.map";`)
	if got := SourceMapURL(source, scriptURL(t, "https://target.test/app.js"), nil); got != "" {
		t.Fatalf("a string mention must not be treated as a directive: %q", got)
	}
}

func TestParseSourceMap(t *testing.T) {
	body := []byte(`{"version":3,"sources":["a.ts"],"sourcesContent":["fetch(\"/api/users\")"]}`)
	sourceMap, err := ParseSourceMap(body)
	if err != nil {
		t.Fatalf("ParseSourceMap: %v", err)
	}
	if sourceMap.Version != 3 || len(sourceMap.SourcesContent) != 1 {
		t.Fatalf("parsed = %+v", sourceMap)
	}
	if !strings.Contains(sourceMap.SourcesContent[0], "/api/users") {
		t.Fatalf("content = %q", sourceMap.SourcesContent[0])
	}
}

func TestParseSourceMapRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"malformed":     `{"version":3,"sources":[`,
		"wrong version": `{"version":2,"sources":[]}`,
		"not an object": `[]`,
	}
	for name, body := range cases {
		if _, err := ParseSourceMap([]byte(body)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestEndpointParameters(t *testing.T) {
	concrete, names := EndpointParameters("/api/users/:id/posts?role=admin&page=2&role=user")
	if concrete != "/api/users/1/posts?role=admin&page=2&role=user" {
		t.Fatalf("concrete = %q", concrete)
	}
	want := []string{"id", "role", "page"}
	if len(names) != len(want) {
		t.Fatalf("names = %#v, want %#v", names, want)
	}
	for index := range want {
		if names[index] != want[index] {
			t.Errorf("name %d = %q, want %q", index, names[index], want[index])
		}
	}
}

func TestEndpointParametersWithoutBindings(t *testing.T) {
	concrete, names := EndpointParameters("/api/health")
	if concrete != "/api/health" || len(names) != 0 {
		t.Fatalf("concrete = %q names = %#v", concrete, names)
	}
}

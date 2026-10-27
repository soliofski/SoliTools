package form

import (
	"net/url"
	"testing"
)

func mustBase(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	return parsed
}

func TestParseFields(t *testing.T) {
	page := []byte(`
		<form action="/search" method="post">
			<input type="text" name="q" value="hello">
			<input type="hidden" name="_token" value="abc123">
			<input type="submit" name="go" value="Search">
			<input type="file" name="attachment">
			<select name="sort"><option>date</option></select>
			<textarea name="note">ignored</textarea>
		</form>`)

	forms := Parse(page, mustBase(t, "https://target.test/list"))
	if len(forms) != 1 {
		t.Fatalf("forms = %d, want 1", len(forms))
	}
	single := forms[0]
	if single.Action != "https://target.test/search" {
		t.Fatalf("action = %q", single.Action)
	}
	if single.Method != "POST" {
		t.Fatalf("method = %q, want POST", single.Method)
	}
	if !single.HasFile {
		t.Fatal("file input was not recorded")
	}

	names := make(map[string]Field, len(single.Fields))
	for _, field := range single.Fields {
		names[field.Name] = field
	}
	if _, ok := names["go"]; ok {
		t.Error("a submit button is not a parameter")
	}
	if _, ok := names["attachment"]; ok {
		t.Error("a file input must not become a parameter")
	}
	if got := names["q"]; got.Value != "hello" || !got.Probe {
		t.Fatalf("q = %+v", got)
	}
	if got := names["_token"]; got.Value != "abc123" || got.Probe {
		t.Fatalf("_token = %+v, want a preserved non-probed field", got)
	}
	if got := names["sort"]; got.Type != "select" || !got.Probe {
		t.Fatalf("sort = %+v", got)
	}
	if got := names["note"]; got.Type != "textarea" {
		t.Fatalf("note = %+v", got)
	}
}

func TestParseActionResolution(t *testing.T) {
	base := mustBase(t, "https://target.test/a/b")

	cases := []struct {
		name   string
		markup string
		want   string
	}{
		{"relative", `<form action="submit"></form>`, "https://target.test/a/submit"},
		{"rooted", `<form action="/submit"></form>`, "https://target.test/submit"},
		{"absolute", `<form action="https://other.test/x"></form>`, "https://other.test/x"},
		{"empty falls back to the page", `<form></form>`, "https://target.test/a/b"},
		{"query only", `<form action="?page=2"></form>`, "https://target.test/a/b?page=2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			forms := Parse([]byte(c.markup), base)
			if len(forms) != 1 {
				t.Fatalf("forms = %d, want 1", len(forms))
			}
			if forms[0].Action != c.want {
				t.Fatalf("action = %q, want %q", forms[0].Action, c.want)
			}
		})
	}
}

func TestParseSkipsUnusableForms(t *testing.T) {
	base := mustBase(t, "https://target.test/")

	cases := []struct {
		name   string
		markup string
	}{
		{"mailto action", `<form action="mailto:test@target.test"><input name="q"></form>`},
		{"javascript action", `<form action="javascript:void(0)"><input name="q"></form>`},
		{"unclosed form", `<form action="/x"><input name="q">`},
		{"unknown method", `<form action="/x" method="PUT"><input name="q"></form>`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if forms := Parse([]byte(c.markup), base); len(forms) != 0 {
				t.Fatalf("forms = %d, want 0: %+v", len(forms), forms)
			}
		})
	}
}

func TestParseMethodDefault(t *testing.T) {
	forms := Parse([]byte(`<form action="/x"><input name="q"></form>`), mustBase(t, "https://target.test/"))
	if len(forms) != 1 || forms[0].Method != "GET" {
		t.Fatalf("forms = %+v, want a single GET form", forms)
	}
}

func TestParseMultipleForms(t *testing.T) {
	page := []byte(`
		<form action="/login" method="post"><input name="user"><input name="pass"></form>
		<form action="/search"><input name="q"></form>`)

	forms := Parse(page, mustBase(t, "https://target.test/"))
	if len(forms) != 2 {
		t.Fatalf("forms = %d, want 2", len(forms))
	}
	if forms[0].Method != "POST" || forms[1].Method != "GET" {
		t.Fatalf("methods = %q, %q", forms[0].Method, forms[1].Method)
	}
}

func TestParseFrameworkFieldsAreNotProbed(t *testing.T) {
	page := []byte(`<form action="/x" method="post">
		<input type="hidden" name="__VIEWSTATE" value="xyz">
		<input type="hidden" name="csrfmiddlewaretoken" value="abc">
		<input name="comment">
	</form>`)

	forms := Parse(page, mustBase(t, "https://target.test/"))
	if len(forms) != 1 {
		t.Fatalf("forms = %d", len(forms))
	}
	probes := forms[0].ProbeFields()
	if len(probes) != 1 || probes[0].Name != "comment" {
		t.Fatalf("probe fields = %+v, want only comment", probes)
	}
	if len(forms[0].Fields) != 3 {
		t.Fatalf("fields = %d, want all three preserved", len(forms[0].Fields))
	}
}

func TestValues(t *testing.T) {
	page := []byte(`<form action="/x" method="post">
		<input name="a" value="1"><input name="b" value="two">
	</form>`)
	forms := Parse(page, mustBase(t, "https://target.test/"))
	values := forms[0].Values()
	if values.Get("a") != "1" || values.Get("b") != "two" {
		t.Fatalf("values = %v", values)
	}
}

func TestLooksDestructive(t *testing.T) {
	cases := []struct {
		name   string
		markup string
		want   bool
	}{
		{"benign", `<form action="/comment" method="post"><input name="text"></form>`, false},
		{"action token", `<form action="/orders/delete" method="post"><input name="id"></form>`, true},
		{"field name", `<form action="/api" method="post"><input name="delete"></form>`, true},
		{"checkout", `<form action="/cart/checkout" method="post"><input name="card"></form>`, true},
		{"substring is not a token", `<form action="/redeletion" method="post"><input name="q"></form>`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			forms := Parse([]byte(c.markup), mustBase(t, "https://target.test/"))
			if len(forms) != 1 {
				t.Fatalf("forms = %d", len(forms))
			}
			if got := forms[0].LooksDestructive(); got != c.want {
				t.Fatalf("LooksDestructive = %v, want %v", got, c.want)
			}
		})
	}
}

func TestParseAttributeEntities(t *testing.T) {
	page := []byte(`<form action="/x"><input name="q" value="a&amp;b"></form>`)
	forms := Parse(page, mustBase(t, "https://target.test/"))
	if len(forms) != 1 || forms[0].Fields[0].Value != "a&b" {
		t.Fatalf("fields = %+v", forms[0].Fields)
	}
}

func TestParseSingleQuotedAttributes(t *testing.T) {
	page := []byte(`<form action='/x' method='post'><input name='q' value='v'></form>`)
	forms := Parse(page, mustBase(t, "https://target.test/"))
	if len(forms) != 1 {
		t.Fatalf("forms = %d", len(forms))
	}
	if forms[0].Action != "https://target.test/x" || forms[0].Fields[0].Name != "q" {
		t.Fatalf("form = %+v", forms[0])
	}
}

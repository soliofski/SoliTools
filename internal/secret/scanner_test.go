package secret

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

const (
	alphaNum     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	upperNum     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	hexLower     = "0123456789abcdef"
	alphaNumDash = alphaNum + "-"
)

// seq returns n characters from alphabet at a stride that is coprime with its
// length, so every character is distinct for n <= len(alphabet). The result is
// deterministic and has high entropy, which makes it a usable stand-in for a
// credential without ever containing one.
func seq(n int, alphabet string, stride int) string {
	var b strings.Builder
	b.Grow(n)
	for i := 0; i < n; i++ {
		b.WriteByte(alphabet[(i*stride+7)%len(alphabet)])
	}
	return b.String()
}

func newScanner(t *testing.T) *Scanner {
	t.Helper()
	scanner, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return scanner
}

func mustSingle(t *testing.T, result Result, wantRule string) findingView {
	t.Helper()
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(result.Findings), result.Findings)
	}
	f := result.Findings[0]
	if f.RuleID != wantRule {
		t.Fatalf("rule = %q, want %q", f.RuleID, wantRule)
	}
	return findingView{f.Category, f.Title, f.Confidence.Value, f.Value, f.Context}
}

type findingView struct {
	category   string
	title      string
	confidence float64
	value      string
	context    string
}

func TestVendorTokenRules(t *testing.T) {
	scanner := newScanner(t)

	cases := []struct {
		name     string
		value    string
		rule     string
		category string
	}{
		{"aws access key id", "AKIA" + seq(16, upperNum, 11), "secret.aws-access-key-id", "AWS"},
		{"github token", "ghp_" + seq(36, alphaNum, 29), "secret.github-token", "GitHub"},
		{"github fine-grained pat", "github_pat_" + seq(22, alphaNum, 29) + "_" + seq(59, alphaNum, 29), "secret.github-fine-grained-pat", "GitHub"},
		{"slack token", "xoxb-" + seq(40, alphaNumDash, 29), "secret.slack-token", "Slack"},
		{"google api key", "AIza" + seq(35, alphaNumDash, 29), "secret.google-api-key", "Google"},
		{"stripe live key", "sk_live_" + seq(24, alphaNum, 29), "secret.stripe-live-key", "Stripe"},
		{"anthropic api key", "sk-ant-api03-" + seq(95, alphaNum, 29), "secret.anthropic-api-key", "Anthropic"},
		{"openai api key", "sk-proj-" + seq(60, alphaNum, 29), "secret.openai-api-key", "OpenAI"},
		{"gitlab pat", "glpat-" + seq(20, alphaNum, 29), "secret.gitlab-pat", "GitLab"},
		{"npm token", "npm_" + seq(36, alphaNum, 29), "secret.npm-token", "npm"},
		{"sendgrid key", "SG." + seq(22, alphaNum, 29) + "." + seq(43, alphaNum, 29), "secret.sendgrid-api-key", "SendGrid"},
		{"twilio api key", "SK" + seq(32, hexLower, 11), "secret.twilio-api-key", "Twilio"},
		{"azure storage key", "AccountKey=" + seq(88, alphaNum, 29), "secret.azure-storage-key", "Azure"},
		{"discord webhook", "https://discord.com/api/webhooks/123456789012345678/" + seq(70, alphaNumDash, 29), "secret.discord-webhook", "Discord"},
		{"telegram bot token", "123456789:" + seq(35, alphaNum, 29), "secret.telegram-bot-token", "Telegram"},
		{"azure sas token", "https://acct.blob.core.windows.net/c/f.txt?sv=2022-11-02&ss=b&srt=sco&sp=rl&se=2026-01-01T00:00:00Z&sig=" + seq(43, alphaNum, 29), "secret.azure-sas-token", "Azure"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := `const apiKey = "` + c.value + `";`
			result := scanner.Scan(Document{Source: "https://target.test/app.js", Body: []byte(body)})
			got := mustSingle(t, result, c.rule)
			if got.category != c.category {
				t.Fatalf("category = %q, want %q", got.category, c.category)
			}
			if got.title == "" {
				t.Fatal("finding has no title")
			}
			if got.context == "" {
				t.Fatal("finding has no context snippet")
			}
			if got.confidence < 60 {
				t.Fatalf("confidence = %v, want at least the default threshold", got.confidence)
			}
		})
	}
}

func testPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return string(pem.EncodeToMemory(block))
}

func TestPrivateKeyRule(t *testing.T) {
	scanner := newScanner(t)

	t.Run("real key block", func(t *testing.T) {
		block := testPrivateKeyPEM(t)
		result := scanner.Scan(Document{Source: "https://target.test/id_rsa", Body: []byte(block)})
		if len(result.Findings) != 1 {
			t.Fatalf("findings = %d, want 1 (reasons %+v)", len(result.Findings), result.ByReason)
		}
		f := result.Findings[0]
		if f.RuleID != "secret.private-key" {
			t.Fatalf("rule = %q", f.RuleID)
		}
		if f.Confidence.Value < 90 {
			t.Fatalf("confidence = %v, want critical", f.Confidence.Value)
		}
		if f.Value != "-----BEGIN RSA PRIVATE KEY-----" {
			t.Fatalf("value = %q, want the header only", f.Value)
		}
		if strings.Contains(f.Context, "MII") {
			t.Fatal("context leaks key material")
		}
	})

	t.Run("json-escaped key block", func(t *testing.T) {
		// A key pasted into a JSON document keeps escaped newlines, which the
		// old body class refused to match.
		block := testPrivateKeyPEM(t)
		escaped := strings.ReplaceAll(block, "\n", `\n`)
		body := `{"private_key":"` + escaped + `"}`

		result := scanner.Scan(Document{Source: "https://target.test/config.json", Body: []byte(body)})
		if len(result.Findings) != 1 {
			t.Fatalf("findings = %d, want 1 (reasons %+v)", len(result.Findings), result.ByReason)
		}
		found := result.Findings[0]
		if found.RuleID != "secret.private-key" {
			t.Fatalf("rule = %q", found.RuleID)
		}
		if found.Value != "-----BEGIN RSA PRIVATE KEY-----" {
			t.Fatalf("value = %q, want the header only", found.Value)
		}
		if strings.Contains(found.Context, "MII") {
			t.Fatalf("context leaks escaped key material: %q", found.Context)
		}
	})

	t.Run("body too small", func(t *testing.T) {
		body := "-----BEGIN RSA PRIVATE KEY-----\nQUJD\n-----END RSA PRIVATE KEY-----\n"
		result := scanner.Scan(Document{Source: "https://target.test/notes.txt", Body: []byte(body)})
		if len(result.Findings) != 0 {
			t.Fatalf("findings = %d, want 0", len(result.Findings))
		}
		if result.ByReason["structure"] != 1 {
			t.Fatalf("reasons = %+v, want one structural rejection", result.ByReason)
		}
	})

	t.Run("mismatched labels", func(t *testing.T) {
		block := testPrivateKeyPEM(t)
		body := strings.Replace(block, "-----END RSA PRIVATE KEY-----", "-----END EC PRIVATE KEY-----", 1)
		if body == block {
			t.Fatal("test setup: footer not replaced")
		}
		result := scanner.Scan(Document{Source: "https://target.test/notes.txt", Body: []byte(body)})
		if len(result.Findings) != 0 {
			t.Fatalf("findings = %d, want 0", len(result.Findings))
		}
		if result.ByReason["structure"] != 1 {
			t.Fatalf("reasons = %+v, want one structural rejection", result.ByReason)
		}
	})
}

func TestHardSuppression(t *testing.T) {
	scanner := newScanner(t)

	cases := []struct {
		name   string
		source string
		body   string
		reason string
	}{
		{"aws documentation example", "https://target.test/app.js", `const id = "AKIAIOSFODNN7EXAMPLE";`, "placeholder"},
		{"padded github token", "https://target.test/app.js", `const t = "ghp_` + strings.Repeat("x", 36) + `";`, "degenerate"},
		{"padded stripe key", "https://target.test/app.js", `const k = "sk_live_` + strings.Repeat("a", 24) + `";`, "degenerate"},
		{"low entropy live key", "https://target.test/app.js", `const k = "sk_live_` + strings.Repeat("ab", 12) + `";`, "degenerate"},
		{"commented out token", "https://target.test/app.js", `// const t = "` + "ghp_" + seq(36, alphaNum, 29) + `";`, "comment"},
		{"html comment token", "https://target.test/index.html", `<!-- token ` + "ghp_" + seq(36, alphaNum, 29) + ` -->`, "comment"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := scanner.Scan(Document{Source: c.source, Body: []byte(c.body)})
			if len(result.Findings) != 0 {
				t.Fatalf("findings = %d, want 0: %+v", len(result.Findings), result.Findings)
			}
			if result.ByReason[c.reason] == 0 {
				t.Fatalf("reasons = %+v, want %q", result.ByReason, c.reason)
			}
		})
	}
}

func TestURLSchemeIsNotAComment(t *testing.T) {
	scanner := newScanner(t)
	token := "ghp_" + seq(36, alphaNum, 29)
	body := `const base = "https://api.target.test/v1"; const token = "` + token + `";`

	result := scanner.Scan(Document{Source: "https://target.test/app.js", Body: []byte(body)})
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v (reasons %+v)", len(result.Findings), result.Findings, result.ByReason)
	}
}

func TestTokenOnCodeLineIsNotAComment(t *testing.T) {
	scanner := newScanner(t)
	token := "ghp_" + seq(36, alphaNum, 29)
	body := "const a = 1 // note\nconst token = \"" + token + "\";\n"

	result := scanner.Scan(Document{Source: "https://target.test/app.js", Body: []byte(body)})
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 (the next line is not a comment)", len(result.Findings))
	}
}

func TestLowConfidenceIsReturnedNotHidden(t *testing.T) {
	scanner := newScanner(t)
	body := `const k = "sk_test_` + seq(24, alphaNum, 29) + `";`

	result := scanner.Scan(Document{Source: "https://target.test/app.js", Body: []byte(body)})
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Findings))
	}
	if got := result.Findings[0].Confidence.Value; got >= 60 {
		t.Fatalf("stripe test key scored %v, want below the default threshold", got)
	}
}

func TestJWTStructure(t *testing.T) {
	scanner := newScanner(t)
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwx"
	body := `localStorage.setItem("token", "` + token + `");`

	result := scanner.Scan(Document{Source: "https://target.test/app.js", Body: []byte(body)})
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(result.Findings), result.Findings)
	}
	f := result.Findings[0]
	if f.RuleID != "secret.jwt" || f.Category != "JWT" {
		t.Fatalf("rule/category = %q/%q", f.RuleID, f.Category)
	}

	structural := false
	for _, signal := range f.Confidence.Signals {
		if signal.Name == "structural" && signal.Delta > 0 {
			structural = true
		}
	}
	if !structural {
		t.Fatalf("signals = %+v, want a structural bonus from the decoded header", f.Confidence.Signals)
	}
}

func TestEntropyGrading(t *testing.T) {
	rule := &Rule{Base: 80, EntropyMin: 3.0}

	cases := []struct {
		payload string
		want    float64
	}{
		{"abcdefghij", 72},                       // 3.32 bits: just above the floor
		{"abcdefghijklmnopqrst", 80},             // 4.32 bits: neutral
		{"abcdefghijklmnopqrstuvwxyz012345", 85}, // 5.0 bits: clearly random
	}
	for _, c := range cases {
		score := scoreCandidate(rule, "", c.payload, Entropy(c.payload))
		if score.Value != c.want {
			t.Errorf("payload %q (%0.2f bits) scored %v, want %v", c.payload, Entropy(c.payload), score.Value, c.want)
		}
	}
}

func TestContextSnippet(t *testing.T) {
	body := strings.Repeat("a", 100) + "SECRET" + strings.Repeat("b", 100)
	got := Context(body, 100, 106, 30)

	if !strings.HasPrefix(got, "...") || !strings.HasSuffix(got, "...") {
		t.Fatalf("context = %q, want ellipsis on both sides", got)
	}
	if !strings.Contains(got, "SECRET") {
		t.Fatalf("context = %q, missing the match", got)
	}
	if len([]rune(got)) > 30+6+30+6 {
		t.Fatalf("context = %q, longer than requested", got)
	}
	if collapsed := Context("a\n\n\t  b", 0, 1, 40); strings.Contains(collapsed, "\n") {
		t.Fatalf("context %q kept a newline", collapsed)
	}
}

func TestMask(t *testing.T) {
	cases := []struct {
		value string
		want  string
	}{
		{"AKIAQ3EGVZ7J4K2WN5TP", "AKIA************N5TP"},
		{"short", "*****"},
		{"", ""},
	}
	for _, c := range cases {
		if got := Mask(c.value); got != c.want {
			t.Errorf("Mask(%q) = %q, want %q", c.value, got, c.want)
		}
	}

	masked := Mask("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----")
	if masked != "-----BEGIN RSA PRIVATE KEY-----" {
		t.Errorf("Mask(PEM) = %q", masked)
	}
}

func TestNewRuleFalsePositives(t *testing.T) {
	scanner := newScanner(t)

	cases := []struct {
		name string
		body string
		rule string
	}{
		{
			"webhook path on another host",
			`https://example.com/api/webhooks/123456789012345678/` + seq(70, alphaNumDash, 29),
			"secret.discord-webhook",
		},
		{
			"bare signature without a SAS version",
			`https://target.test/cb?state=1&sig=` + seq(43, alphaNum, 29),
			"secret.azure-sas-token",
		},
		{
			"telegram-shaped but too short",
			`build 12345678:shortlog`,
			"secret.telegram-bot-token",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := scanner.Scan(Document{Source: "https://target.test/app.js", Body: []byte(c.body)})
			for _, found := range result.Findings {
				if found.RuleID == c.rule {
					t.Fatalf("%s matched %q: %+v", c.rule, c.body, found)
				}
			}
		})
	}
}

func TestBinaryInput(t *testing.T) {
	scanner := newScanner(t)
	body := append([]byte("ghp_"+seq(36, alphaNum, 29)), 0x00, 0x01)
	if result := scanner.Scan(Document{Source: "https://target.test/blob", Body: body}); len(result.Findings) != 0 {
		t.Fatalf("binary input produced findings")
	}
}

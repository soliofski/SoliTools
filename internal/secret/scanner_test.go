package secret

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
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

func newScanner(t *testing.T, opts Options) *Scanner {
	t.Helper()
	scanner, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return scanner
}

// assertSingleFinding fails unless the result holds exactly one finding for the
// expected rule. Extra findings are treated as failures: collateral matches are
// how a detector loses precision.
func assertSingleFinding(t *testing.T, result FileResult, wantRule string) findingView {
	t.Helper()
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(result.Findings), result.Findings)
	}
	f := result.Findings[0]
	if f.RuleID != wantRule {
		t.Fatalf("rule = %q, want %q", f.RuleID, wantRule)
	}
	return findingView{f.RuleID, f.Confidence.Value, f.Match, f.Fingerprint}
}

type findingView struct {
	ruleID      string
	confidence  float64
	match       string
	fingerprint string
}

func TestVendorTokenRules(t *testing.T) {
	scanner := newScanner(t, Options{})

	cases := []struct {
		name       string
		value      string
		rule       string
		confidence float64
	}{
		{"aws access key id", "AKIA" + seq(16, upperNum, 11), "secret.aws-access-key-id", 85},
		{"github token", "ghp_" + seq(36, alphaNum, 29), "secret.github-token", 90},
		{"github fine-grained pat", "github_pat_" + seq(22, alphaNum, 29) + "_" + seq(59, alphaNum, 29), "secret.github-fine-grained-pat", 90},
		{"slack token", "xoxb-" + seq(40, alphaNumDash, 29), "secret.slack-token", 85},
		{"google api key", "AIza" + seq(35, alphaNumDash, 29), "secret.google-api-key", 80},
		{"stripe live key", "sk_live_" + seq(24, alphaNum, 29), "secret.stripe-live-key", 90},
		{"anthropic api key", "sk-ant-api03-" + seq(95, alphaNum, 29), "secret.anthropic-api-key", 90},
		{"openai api key", "sk-proj-" + seq(60, alphaNum, 29), "secret.openai-api-key", 85},
		{"gitlab pat", "glpat-" + seq(20, alphaNum, 29), "secret.gitlab-pat", 85},
		{"npm token", "npm_" + seq(36, alphaNum, 29), "secret.npm-token", 85},
		{"sendgrid key", "SG." + seq(22, alphaNum, 29) + "." + seq(43, alphaNum, 29), "secret.sendgrid-api-key", 85},
		{"twilio api key", "SK" + seq(32, hexLower, 11), "secret.twilio-api-key", 70},
		{"azure storage key", "AccountKey=" + seq(88, alphaNum, 29), "secret.azure-storage-key", 85},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			content := "api_key = \"" + c.value + "\"\n"
			result := scanner.ScanText("internal/app/config.go", []byte(content))
			got := assertSingleFinding(t, result, c.rule)
			if got.confidence != c.confidence {
				t.Fatalf("confidence = %v, want %v", got.confidence, c.confidence)
			}
			if !strings.Contains(got.match, "*") {
				t.Fatalf("match %q is not redacted", got.match)
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
	scanner := newScanner(t, Options{})

	t.Run("real key block", func(t *testing.T) {
		block := testPrivateKeyPEM(t)
		result := scanner.ScanText("deploy/id_rsa", []byte(block))
		if len(result.Findings) != 1 {
			t.Fatalf("findings = %d, want 1", len(result.Findings))
		}
		f := result.Findings[0]
		if f.RuleID != "secret.private-key" {
			t.Fatalf("rule = %q", f.RuleID)
		}
		if f.Confidence.Value != 95 {
			t.Fatalf("confidence = %v, want 95", f.Confidence.Value)
		}
		if f.Match != "-----BEGIN RSA PRIVATE KEY----- [body redacted]" {
			t.Fatalf("match = %q, want header only", f.Match)
		}
		body := strings.Split(block, "\n")[1]
		if body != "" && strings.Contains(f.Match, body) {
			t.Fatal("redacted match leaks key material")
		}
	})

	t.Run("body too small", func(t *testing.T) {
		content := "-----BEGIN RSA PRIVATE KEY-----\nQUJD\n-----END RSA PRIVATE KEY-----\n"
		result := scanner.ScanText("notes.txt", []byte(content))
		if len(result.Findings) != 0 {
			t.Fatalf("findings = %d, want 0", len(result.Findings))
		}
		if result.Stats.ByReason["structure"] != 1 {
			t.Fatalf("reasons = %+v, want one structural rejection", result.Stats.ByReason)
		}
	})

	t.Run("mismatched labels", func(t *testing.T) {
		block := testPrivateKeyPEM(t)
		content := strings.Replace(block, "-----END RSA PRIVATE KEY-----", "-----END EC PRIVATE KEY-----", 1)
		if content == block {
			t.Fatal("test setup: footer not replaced")
		}
		result := scanner.ScanText("notes.txt", []byte(content))
		if len(result.Findings) != 0 {
			t.Fatalf("findings = %d, want 0", len(result.Findings))
		}
		if result.Stats.ByReason["structure"] != 1 {
			t.Fatalf("reasons = %+v, want one structural rejection", result.Stats.ByReason)
		}
	})

	t.Run("unterminated header", func(t *testing.T) {
		content := "-----BEGIN RSA PRIVATE KEY-----\nQUJD\n"
		result := scanner.ScanText("notes.txt", []byte(content))
		if len(result.Findings) != 0 {
			t.Fatalf("findings = %d, want 0", len(result.Findings))
		}
	})
}

func TestFalsePositivesAreSuppressed(t *testing.T) {
	scanner := newScanner(t, Options{})

	cases := []struct {
		name   string
		path   string
		value  string
		reason string
	}{
		{"aws documentation example", "internal/aws/client.go", "AKIAIOSFODNN7EXAMPLE", "placeholder"},
		{"padded github token", "app.go", "ghp_" + strings.Repeat("x", 36), "degenerate"},
		{"padded stripe key", "app.go", "sk_live_" + strings.Repeat("a", 24), "degenerate"},
		{"stripe test key", "app.go", "sk_test_" + seq(24, alphaNum, 29), "below-threshold"},
		{"token too short", "app.go", "ghp_" + seq(20, alphaNum, 29), ""},
		{"google key too short", "app.go", "AIza" + seq(34, alphaNumDash, 29), ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := scanner.ScanText(c.path, []byte("key = \""+c.value+"\"\n"))
			if len(result.Findings) != 0 {
				t.Fatalf("findings = %d, want 0: %+v", len(result.Findings), result.Findings)
			}
			if c.reason != "" && result.Stats.ByReason[c.reason] == 0 {
				t.Fatalf("reasons = %+v, want %q", result.Stats.ByReason, c.reason)
			}
		})
	}
}

func TestPathPenaltyLowersButKeepsFinding(t *testing.T) {
	scanner := newScanner(t, Options{})
	token := "ghp_" + seq(36, alphaNum, 29)
	content := "token = \"" + token + "\"\n"

	cases := []struct {
		path string
		want float64
	}{
		{"internal/app/config.go", 90},
		{"testdata/fixture.go", 70},
		{"examples/demo.env", 80},
		{"README.md", 80},
	}
	for _, c := range cases {
		result := scanner.ScanText(c.path, []byte(content))
		if len(result.Findings) != 1 {
			t.Fatalf("%s: findings = %d, want 1", c.path, len(result.Findings))
		}
		if got := result.Findings[0].Confidence.Value; got != c.want {
			t.Errorf("%s: confidence = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestGenericRulesetIsOptIn(t *testing.T) {
	value := seq(20, alphaNum, 29)
	content := "password = \"" + value + "\"\n"

	def := newScanner(t, Options{})
	if result := def.ScanText("config.py", []byte(content)); len(result.Findings) != 0 {
		t.Fatalf("default scanner reported %d findings for a generic assignment", len(result.Findings))
	}

	generic := newScanner(t, Options{IncludeGeneric: true})
	result := generic.ScanText("config.py", []byte(content))
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Findings))
	}
	f := result.Findings[0]
	if f.RuleID != "secret.generic-assignment" {
		t.Fatalf("rule = %q", f.RuleID)
	}
	if f.Confidence.Value != 45 {
		t.Fatalf("confidence = %v, want 45 (55 base, -10 generic)", f.Confidence.Value)
	}
	if len(f.Confidence.Signals) != 1 || f.Confidence.Signals[0].Name != "generic-rule" {
		t.Fatalf("signals = %+v", f.Confidence.Signals)
	}
	if strings.Contains(f.Match, "password") {
		t.Errorf("match %q still shows the keyword instead of the secret", f.Match)
	}
	if !strings.HasPrefix(f.Match, value[:4]) {
		t.Errorf("match %q lost the secret head", f.Match)
	}
	if want := strings.Index(content, value) + 1; f.Column != want {
		t.Errorf("column = %d, want %d (start of the captured value)", f.Column, want)
	}

	placeholder := generic.ScanText("config.py", []byte("password = \"changeme123456\"\n"))
	if len(placeholder.Findings) != 0 {
		t.Fatalf("placeholder reported as finding: %+v", placeholder.Findings)
	}
	if placeholder.Stats.ByReason["placeholder"] == 0 {
		t.Fatalf("reasons = %+v, want placeholder", placeholder.Stats.ByReason)
	}
}

func TestLocationsAndRedaction(t *testing.T) {
	scanner := newScanner(t, Options{})
	token := "ghp_" + seq(36, alphaNum, 29)
	content := "package x\n\nvar token = \"" + token + "\"\n\nvar again = \"" + token + "\"\n"

	result := scanner.ScanText("internal/app/config.go", []byte(content))
	if len(result.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(result.Findings))
	}

	first := result.Findings[0]
	if first.Line != 3 {
		t.Errorf("line = %d, want 3", first.Line)
	}
	if first.Column != 14 {
		t.Errorf("column = %d, want 14", first.Column)
	}
	if !strings.HasPrefix(first.Match, "ghp_") {
		t.Errorf("match %q lost its prefix", first.Match)
	}
	if !strings.HasSuffix(first.Match, token[len(token)-2:]) {
		t.Errorf("match %q lost its suffix", first.Match)
	}
	if strings.Contains(first.Match, token[8:30]) {
		t.Errorf("match %q leaks the secret body", first.Match)
	}
	if want := Fingerprint(token[len("ghp_"):]); first.Fingerprint != want {
		t.Errorf("fingerprint = %q, want %q", first.Fingerprint, want)
	}
	if second := result.Findings[1]; second.Line != 5 {
		t.Errorf("second line = %d, want 5", second.Line)
	}
}

func TestCaptureGroupDrivesReportedValue(t *testing.T) {
	scanner := newScanner(t, Options{})
	key := seq(88, alphaNum, 29)
	content := `connection = "DefaultEndpointsProtocol=https;AccountKey=` + key + `;EndpointSuffix=core.windows.net"` + "\n"

	result := scanner.ScanText("app/config.go", []byte(content))
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Findings))
	}
	f := result.Findings[0]
	if strings.Contains(f.Match, "AccountKey") {
		t.Errorf("match %q shows the surrounding syntax", f.Match)
	}
	if !strings.HasPrefix(f.Match, key[:4]) {
		t.Errorf("match %q lost the key head", f.Match)
	}
	if !strings.HasSuffix(f.Match, key[len(key)-2:]) {
		t.Errorf("match %q lost the key tail", f.Match)
	}
	if want := strings.Index(content, key) + 1; f.Column != want {
		t.Errorf("column = %d, want %d", f.Column, want)
	}
}

func TestBinaryAndEmptyInput(t *testing.T) {
	scanner := newScanner(t, Options{})
	token := []byte("ghp_" + seq(36, alphaNum, 29))

	binary := append(append([]byte{}, token...), 0x00, 0x01)
	result := scanner.ScanText("blob.bin", binary)
	if len(result.Findings) != 0 {
		t.Fatalf("binary input produced findings")
	}
	if result.Stats.FilesSkipped != 1 {
		t.Fatalf("skipped = %d, want 1", result.Stats.FilesSkipped)
	}

	empty := scanner.ScanText("empty.go", nil)
	if len(empty.Findings) != 0 || empty.Stats.FilesScanned != 1 {
		t.Fatalf("empty input: findings=%d scanned=%d", len(empty.Findings), empty.Stats.FilesScanned)
	}
}

func TestScanPathsWalksAndSkipsNoise(t *testing.T) {
	scanner := newScanner(t, Options{})
	root := t.TempDir()
	token := "ghp_" + seq(36, alphaNum, 29)

	write := func(rel, content string) {
		t.Helper()
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	write(filepath.Join("app", "config.env"), "token = \""+token+"\"\n")
	write(filepath.Join(".git", "config"), "token = \""+token+"\"\n")
	write(filepath.Join("node_modules", "pkg", "index.js"), "token = \""+token+"\"\n")
	write(filepath.Join("assets", "logo.png"), "\x00\x01binary")

	report, err := scanner.ScanPaths(t.Context(), []string{root})
	if err != nil {
		t.Fatalf("ScanPaths: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(report.Findings), report.Findings)
	}
	if !strings.HasSuffix(report.Findings[0].File, filepath.Join("app", "config.env")) {
		t.Fatalf("unexpected file %q", report.Findings[0].File)
	}
	if report.Stats.FilesScanned != 1 {
		t.Fatalf("scanned = %d, want 1", report.Stats.FilesScanned)
	}

	single, err := scanner.ScanPaths(t.Context(), []string{filepath.Join(root, "app", "config.env")})
	if err != nil {
		t.Fatalf("ScanPaths single file: %v", err)
	}
	if len(single.Findings) != 1 {
		t.Fatalf("single file findings = %d, want 1", len(single.Findings))
	}

	if _, err := scanner.ScanPaths(t.Context(), []string{filepath.Join(root, "does-not-exist")}); err == nil {
		t.Fatal("missing path must return an error")
	}
}

func TestNewRejectsInvalidRules(t *testing.T) {
	if _, err := New(Options{MinConfidence: -1}); err != nil {
		t.Fatalf("negative min confidence should fall back to the default: %v", err)
	}
	if _, err := New(Options{IncludeGeneric: true}); err != nil {
		t.Fatalf("New with generic rules: %v", err)
	}
}

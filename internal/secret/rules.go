package secret

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/soliofski/SoliTools/internal/confidence"
)

// Rules returns the full detector set.
//
// Inclusion bar for a high base score: the pattern must encode provider
// identity — a reserved prefix or an unambiguous structure. The generic rules
// at the end match a shape rather than a provider, so they carry a penalty and
// land below the default display threshold; they surface with --all.
func Rules() []*Rule {
	return []*Rule{
		{
			ID:          "secret.private-key",
			Title:       "Private Key Block",
			Category:    "Private Key",
			Description: "PEM-encoded private key material",
			Base:        95,
			// The body class also allows a backslash, because a key pasted into
			// JSON arrives as "-----BEGIN …\n…-----END" with escaped newlines.
			Pattern: `(?s)-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----([A-Za-z0-9+/=\s\\]+?)-----END ([A-Z0-9 ]*PRIVATE KEY)-----`,
			Group:   2,
			// A header/footer pair alone appears in documentation and in code
			// that parses keys; only a body that base64-decodes to real DER
			// material is treated as key material.
			Require:         requirePEMBlock,
			RedactFullMatch: true,
			ShieldGeneric:   true,
		},
		{
			ID:          "secret.aws-access-key-id",
			Title:       "AWS Access Key",
			Category:    "AWS",
			Description: "AWS access key identifier",
			Base:        85,
			Pattern:     `\b(?:AKIA|ASIA|ABIA|ACCA|AIDA|AIPA|ANPA|ANVA|AROA|APKA)[A-Z0-9]{16}\b`,
			Prefixes:    []string{"AKIA", "ASIA", "ABIA", "ACCA", "AIDA", "AIPA", "ANPA", "ANVA", "AROA", "APKA"},
			MinLen:      16,
			MaxLen:      16,
			EntropyMin:  3.0,
		},
		{
			ID:          "secret.github-token",
			Title:       "GitHub Token",
			Category:    "GitHub",
			Description: "GitHub personal access, OAuth or server token",
			Base:        90,
			Pattern:     `\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b`,
			Prefixes:    []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
			MinLen:      36,
			MaxLen:      36,
			EntropyMin:  3.5,
		},
		{
			ID:          "secret.github-fine-grained-pat",
			Title:       "GitHub Fine-Grained Token",
			Category:    "GitHub",
			Description: "GitHub fine-grained personal access token",
			Base:        90,
			Pattern:     `\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b`,
			Prefixes:    []string{"github_pat_"},
			MinLen:      82,
			MaxLen:      82,
			EntropyMin:  3.5,
		},
		{
			ID:          "secret.slack-token",
			Title:       "Slack Token",
			Category:    "Slack",
			Description: "Slack bot, user or app token",
			Base:        85,
			Pattern:     `\bxox[baprs]-[A-Za-z0-9-]{10,120}\b`,
			Prefixes:    []string{"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"},
			MinLen:      10,
			MaxLen:      120,
			EntropyMin:  2.0,
		},
		{
			ID:          "secret.google-api-key",
			Title:       "Google API Key",
			Category:    "Google",
			Description: "Google API key (AIza prefix)",
			Base:        80,
			Pattern:     `\bAIza[0-9A-Za-z_-]{35}\b`,
			Prefixes:    []string{"AIza"},
			MinLen:      35,
			MaxLen:      35,
			EntropyMin:  3.0,
		},
		{
			ID:          "secret.stripe-live-key",
			Title:       "Stripe Live Key",
			Category:    "Stripe",
			Description: "Stripe live secret or restricted key",
			Base:        90,
			Pattern:     `\b(?:sk|rk)_live_[0-9A-Za-z]{24,247}\b`,
			Prefixes:    []string{"sk_live_", "rk_live_"},
			MinLen:      24,
			MaxLen:      247,
			EntropyMin:  3.0,
		},
		{
			ID:          "secret.stripe-test-key",
			Title:       "Stripe Test Key",
			Category:    "Stripe",
			Description: "Stripe test-mode key; cannot move real money",
			Base:        30,
			Pattern:     `\b(?:sk|rk)_test_[0-9A-Za-z]{24,247}\b`,
			Prefixes:    []string{"sk_test_", "rk_test_"},
			MinLen:      24,
			MaxLen:      247,
			EntropyMin:  3.0,
		},
		{
			ID:          "secret.anthropic-api-key",
			Title:       "Anthropic API Key",
			Category:    "Anthropic",
			Description: "Anthropic API key",
			Base:        90,
			Pattern:     `\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{40,}\b`,
			MinLen:      40,
			EntropyMin:  3.5,
		},
		{
			ID:          "secret.openai-api-key",
			Title:       "OpenAI API Key",
			Category:    "OpenAI",
			Description: "OpenAI project, service-account or admin key",
			Base:        85,
			Pattern:     `\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}\b`,
			MinLen:      20,
			EntropyMin:  3.5,
		},
		{
			ID:          "secret.gitlab-pat",
			Title:       "GitLab Personal Access Token",
			Category:    "GitLab",
			Description: "GitLab personal access token",
			Base:        85,
			Pattern:     `\bglpat-[A-Za-z0-9_-]{20}\b`,
			Prefixes:    []string{"glpat-"},
			MinLen:      20,
			MaxLen:      20,
			EntropyMin:  3.0,
		},
		{
			ID:          "secret.npm-token",
			Title:       "npm Token",
			Category:    "npm",
			Description: "npm registry access token",
			Base:        85,
			Pattern:     `\bnpm_[A-Za-z0-9]{36}\b`,
			Prefixes:    []string{"npm_"},
			MinLen:      36,
			MaxLen:      36,
			EntropyMin:  3.5,
		},
		{
			ID:          "secret.sendgrid-api-key",
			Title:       "SendGrid API Key",
			Category:    "SendGrid",
			Description: "SendGrid API key",
			Base:        85,
			Pattern:     `\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`,
			Prefixes:    []string{"SG."},
			MinLen:      66,
			MaxLen:      66,
			EntropyMin:  3.5,
		},
		{
			ID:          "secret.twilio-api-key",
			Title:       "Twilio API Key",
			Category:    "Twilio",
			Description: "Twilio API key SID",
			Base:        70,
			Pattern:     `\bSK[0-9a-fA-F]{32}\b`,
			Prefixes:    []string{"SK"},
			MinLen:      32,
			MaxLen:      32,
			EntropyMin:  2.5,
		},
		{
			ID:          "secret.azure-storage-key",
			Title:       "Azure Storage Account Key",
			Category:    "Azure",
			Description: "Azure Storage connection string account key",
			Base:        85,
			Pattern:     `AccountKey=([A-Za-z0-9+/=]{86,90})`,
			Group:       1,
			MinLen:      86,
			MaxLen:      90,
			EntropyMin:  4.0,
		},
		{
			ID:          "secret.discord-webhook",
			Title:       "Discord Webhook URL",
			Category:    "Discord",
			Description: "Discord webhook endpoint, which accepts messages without further authentication",
			Base:        90,
			Pattern:     `https://(?:(?:ptb|canary)\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{60,80}`,
			EntropyMin:  3.0,
		},
		{
			ID:          "secret.telegram-bot-token",
			Title:       "Telegram Bot Token",
			Category:    "Telegram",
			Description: "Telegram bot API token (bot id and secret)",
			Base:        85,
			Pattern:     `\b\d{8,10}:[A-Za-z0-9_-]{35}\b`,
			MinLen:      44,
			MaxLen:      46,
			EntropyMin:  3.5,
		},
		{
			ID:       "secret.azure-sas-token",
			Title:    "Azure SAS Token",
			Category: "Azure",
			// A signature only matters with the parameters that scope it, so the
			// pattern requires the SAS version stamp in front and captures the
			// signature; matching a bare ?sig= would hit every HMAC on the web.
			// The parameter run is a flat character class: RE2 refuses a counted
			// repetition nested inside another one.
			Description: "Azure Storage shared access signature",
			Base:        72,
			Pattern:     `[?&]sv=\d{4}-\d{2}-\d{2}[A-Za-z0-9%._~+/=&:-]{0,512}?sig=([A-Za-z0-9%+/=_.~-]{20,200})`,
			Group:       1,
			MinLen:      20,
			MaxLen:      200,
			EntropyMin:  4.0,
			Validate:    validateSAS,
		},
		{
			ID:          "secret.jwt",
			Title:       "JSON Web Token",
			Category:    "JWT",
			Description: "Signed JWT in a response body",
			Base:        55,
			Pattern:     `\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,}\b`,
			MinLen:      25,
			EntropyMin:  3.0,
			// A JWT is only interesting if its header actually parses as JWT
			// metadata; a random "eyJ..." triple is not a token.
			Validate: validateJWT,
		},
		{
			ID:          "secret.generic-assignment",
			Title:       "Assigned Credential",
			Category:    "Generic Secret",
			Description: "Keyword assignment holding a high-entropy value",
			Base:        50,
			Pattern:     `(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd)\b\s*[:=]\s*["']([^"'\r\n]{12,128})["']`,
			Group:       1,
			MinLen:      12,
			MaxLen:      128,
			EntropyMin:  3.2,
			Generic:     true,
		},
		{
			ID:          "secret.generic-high-entropy",
			Title:       "High-Entropy String",
			Category:    "Generic Secret",
			Description: "Long random-looking string with no provider identity",
			Base:        40,
			Pattern:     `\b[A-Za-z0-9+/_-]{40,64}\b`,
			MinLen:      40,
			MaxLen:      64,
			EntropyMin:  4.2,
			Generic:     true,
		},
	}
}

// pemEscapes removes the literal escape sequences a JSON-encoded PEM carries in
// place of line breaks. A real PEM body never contains a backslash, so this is a
// no-op for the common case.
var pemEscapes = strings.NewReplacer(
	`\n`, "",
	`\r`, "",
	`\t`, "",
)

// requirePEMBlock accepts a PEM block only when the BEGIN and END labels agree
// and the body decodes to plausible DER material.
func requirePEMBlock(full, payload string) bool {
	begin, okBegin := pemLabel(full, "-----BEGIN ")
	end, okEnd := pemLabel(full, "-----END ")
	if !okBegin || !okEnd || begin != end {
		return false
	}

	body := pemEscapes.Replace(stripSpaces(payload))
	if len(body) < 64 {
		return false
	}
	der, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return false
	}
	return len(der) >= 64
}

// validateSAS adds confidence when other SAS parameters accompany the
// signature: a version stamp alone could be anything, but sv= plus sp= or se=
// is unmistakably a storage SAS.
func validateSAS(full, _ string) (confidence.Signal, bool) {
	lower := strings.ToLower(full)
	markers := 0
	for _, marker := range []string{"&sp=", "&se=", "&ss=", "&srt=", "&spr=", "&si="} {
		if strings.Contains(lower, marker) {
			markers++
		}
	}
	if markers == 0 {
		return confidence.Signal{}, false
	}
	return confidence.Signal{
		Name:   "structural",
		Delta:  8,
		Reason: "signature is scoped by additional SAS parameters",
	}, true
}

// pemLabel returns the text between marker and the next "-----".
func pemLabel(block, marker string) (string, bool) {
	start := strings.Index(block, marker)
	if start < 0 {
		return "", false
	}
	rest := block[start+len(marker):]
	end := strings.Index(rest, "-----")
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}

// validateJWT adds confidence only when the header segment decodes to JSON that
// names a signing algorithm.
func validateJWT(_, payload string) (confidence.Signal, bool) {
	parts := strings.Split(payload, ".")
	if len(parts) != 3 {
		return confidence.Signal{}, false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return confidence.Signal{}, false
	}
	var parsed struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(header, &parsed); err != nil || parsed.Alg == "" {
		return confidence.Signal{}, false
	}
	return confidence.Signal{
		Name:   "structural",
		Delta:  10,
		Reason: "JWT header decodes and declares alg=" + parsed.Alg,
	}, true
}

package secret

import (
	"encoding/base64"
	"strings"
)

// HighPrecisionRules returns the detectors enabled by default.
//
// Inclusion bar: the pattern must encode provider identity — a reserved prefix
// or an unambiguous structure. Nothing here relies on a bare keyword plus
// entropy, because that combination is the dominant source of false positives
// in secret scanning. A rule that would need a human to judge context belongs
// in the generic set instead.
func HighPrecisionRules() []*Rule {
	return []*Rule{
		{
			ID:          "secret.private-key",
			Name:        "Private key block",
			Description: "PEM-encoded private key material",
			Base:        95,
			Pattern:     `(?s)-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----([A-Za-z0-9+/=\s]+?)-----END ([A-Z0-9 ]*PRIVATE KEY)-----`,
			Group:       2,
			// A header/footer pair alone appears in documentation and in code
			// that parses keys; only a body that base64-decodes to real DER
			// material is treated as key material.
			Require:         requirePEMBlock,
			RedactFullMatch: true,
		},
		{
			ID:          "secret.aws-access-key-id",
			Name:        "AWS access key ID",
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
			Name:        "GitHub token",
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
			Name:        "GitHub fine-grained PAT",
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
			Name:        "Slack token",
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
			Name:        "Google API key",
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
			Name:        "Stripe live key",
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
			Name:        "Stripe test key",
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
			Name:        "Anthropic API key",
			Description: "Anthropic API key",
			Base:        90,
			Pattern:     `\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{40,}\b`,
			MinLen:      40,
			EntropyMin:  3.5,
		},
		{
			ID:          "secret.openai-api-key",
			Name:        "OpenAI API key",
			Description: "OpenAI project, service-account or admin key",
			Base:        85,
			Pattern:     `\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}\b`,
			MinLen:      20,
			EntropyMin:  3.5,
		},
		{
			ID:          "secret.gitlab-pat",
			Name:        "GitLab personal access token",
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
			Name:        "npm token",
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
			Name:        "SendGrid API key",
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
			Name:        "Twilio API key",
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
			Name:        "Azure storage account key",
			Description: "Azure Storage connection string account key",
			Base:        85,
			Pattern:     `AccountKey=([A-Za-z0-9+/=]{86,90})`,
			Group:       1,
			MinLen:      86,
			MaxLen:      90,
			EntropyMin:  4.0,
		},
	}
}

// GenericRules returns the opt-in, low-precision detectors.
//
// These match a shape rather than a provider, so they are the ones that
// generate noise. They are kept out of the default set so the default output
// stays actionable; enabling them is an explicit trade of precision for recall.
func GenericRules() []*Rule {
	return []*Rule{
		{
			ID:          "secret.generic-assignment",
			Name:        "Assigned credential",
			Description: "Keyword assignment holding a high-entropy value",
			Base:        55,
			Pattern:     `(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd)\b\s*[:=]\s*["']([^"'\r\n]{12,128})["']`,
			Group:       1,
			MinLen:      12,
			MaxLen:      128,
			EntropyMin:  3.2,
			Generic:     true,
		},
		{
			ID:          "secret.generic-high-entropy",
			Name:        "High-entropy string",
			Description: "Long random-looking string with no provider identity",
			Base:        45,
			Pattern:     `\b[A-Za-z0-9+/_-]{40,64}\b`,
			MinLen:      40,
			MaxLen:      64,
			EntropyMin:  4.2,
			Generic:     true,
		},
	}
}

// requirePEMBlock accepts a PEM block only when the BEGIN and END labels agree
// and the body decodes to plausible DER material.
func requirePEMBlock(full, payload string) bool {
	begin, okBegin := pemLabel(full, "-----BEGIN ")
	end, okEnd := pemLabel(full, "-----END ")
	if !okBegin || !okEnd || begin != end {
		return false
	}

	body := stripSpaces(payload)
	if len(body) < 64 {
		return false
	}
	der, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return false
	}
	return len(der) >= 64
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

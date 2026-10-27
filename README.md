# SoliTools

High-accuracy web security scanner in Go, built for penetration testing and bug
bounty work. The guiding rule: **a finding must be worth a human's time**.
Precision beats recall at every decision point, and everything filtered out is
counted and explained rather than silently dropped.

Architecture, maintenance notes, known traps and the design rationale live in
[HANDOVER.md](HANDOVER.md); this file covers usage.

> Use SoliTools only against systems you are authorized to test. It sends real
> HTTP requests, including harmless canary payloads.

## Build

Go 1.21 or newer, no external dependencies (stdlib only, builds offline):

```console
go build -o solitools ./cmd/solitools
go test ./...
```

## Usage

```console
solitools scan [flags] <url>
```

```console
$ solitools scan https://target.example/
[SECRET] [95] GitHub Token
URL: https://target.example/static/app.js
Value: ghp_********************************Ge3N
Context: ...const token = "ghp_********************************Ge3N"; fetch("/api/v1...
Line: 1:120
Entropy: 5.06 bits/symbol
Occurrences: 2

[REFLECT] [90] Potential Reflected XSS
URL: https://target.example/search?q=hello
Value: soli<x3z>yq
Context: ...<p>soli<x3z>yq</p>...
Parameter: q
Reflection Point: HTML body
Payload: soli<x3z>yq
Status: 200

Target: https://target.example/
Requests: 41  Pages: 1  Scripts: 3  Endpoints: 12  Parameters: 4
Findings: 2 (1 critical, 1 high)
Filtered at detection: 6 (placeholder 4, superseded 2)
```

Exit codes: `0` nothing at the selected threshold, `1` findings reported, `2`
usage or runtime error.

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-strict` | off | only show findings with confidence ≥ 75 |
| `-all` | off | show everything, including low confidence |
| `-min-score` | unset | explicit threshold; overrides `-strict`/`-all` |
| `-mask` | **true** | mask secret values (pass `-mask=false` to reveal) |
| `-rate` | 10 | maximum requests per second, shared by all modules |
| `-proxy` | none | HTTP/HTTPS/SOCKS5 proxy URL |
| `-header` | none | extra request header, `"Name: value"`, repeatable |
| `-cookie` | none | raw Cookie header value |
| `-timeout` | 15s | per-request timeout |
| `-max-params` | 10 | parameters actively probed |
| `-skip-path` | off | skip the sensitive-path wordlist |
| `-verbose` | off | print the score derivation |
| `-json` | off | machine-readable report |
| `-quiet` | off | one-line summary only (CI mode); implies plain output |
| `-width` | 0 | wrap to this many columns; `0` detects the terminal |
| `-color` | `auto` | `auto`, `always` or `never`; `auto` colors only on a terminal |

Authentication is `-header "Authorization: Bearer …"` plus `-cookie`.

### Terminal experience

Output is styled for a real terminal and plain everywhere else:

- module badges are colored per kind — `SECRET` magenta, `REFLECT` cyan,
  `REDIRECT` yellow, `PATH` blue;
- the score badge follows its band, from grey (`low`) to bright red (`critical`);
- secret values are highlighted in amber, URLs in near-white, labels in grey;
- while a scan runs, a single line shows a spinner, the current stage and a live
  request counter;
- the run ends with a boxed summary of findings, bands, traffic and everything
  that was filtered.

Color appears only when stdout is an interactive terminal. `NO_COLOR`,
`CLICOLOR=0` and `TERM=dumb` turn it off, `-color=always` forces it (including
into a pipe) and `-color=never` removes it entirely. JSON output is never
styled, and the animated status line requires a real terminal so redirected
output never collects carriage returns.

Long values wrap to the detected terminal width, with continuation lines
aligned under the value column. Wrapping understands the content it breaks:
a word is kept whole where possible, an unbreakable token is split at a path
separator, an HTML tag is never cut in half, and a `URL` line is left intact
because a split URL cannot be copied. Use `-width N` to pin the width
(useful for reproducible reports); redirected output is never wrapped unless
a width is given.

`-quiet` prints a single line such as `4 findings · 30 requests · 3 critical,
1 high` and nothing else — no banner, no detail, no animation — while keeping
the exit code semantics. It is meant for CI logs.

On Windows the console is switched into VT mode first; if that fails the tool
falls back to plain text rather than printing raw escape codes.

## Confidence model

Every finding starts at the base confidence its detector declares and is
adjusted by named signals. The full trace is attached to each finding, so any
score can be reconstructed and argued with after the fact.

| Band | Range | Meaning |
| --- | --- | --- |
| `critical` | 90–100 | vendor-identified, structurally valid, or verified by the protocol |
| `high` | 75–89 | likely real; `-strict` starts here |
| `medium-high` | 60–74 | **default display threshold** |
| `medium` | 40–59 | only with `-all` |
| `low` | < 40 | likely noise |

Two mechanisms are kept strictly apart:

- **Gates** reject a candidate outright — a malformed value is not a weak
  finding, it is not a finding. Gates never produce a score.
- **Signals** adjust confidence and always appear in the trace.

Everything suppressed is counted per reason and printed in the summary, so a
filter can be audited instead of trusted.

## Modules

### secret — credential detection

Rules must encode provider identity: a reserved prefix (`ghp_`, `sk_live_`,
`AIza`, …) or an unambiguous structure. Nothing in the high-scoring set is
"keyword plus entropy", which is the dominant source of false positives.

| Category | Rule | Base | Hard requirements |
| --- | --- | --- | --- |
| Private Key | `secret.private-key` | 95 | PEM body must base64-decode to ≥ 64 bytes of DER |
| AWS | `secret.aws-access-key-id` | 85 | prefix + 16 chars, entropy ≥ 3.0 |
| GitHub | `secret.github-token` | 90 | `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 36, entropy ≥ 3.5 |
| GitHub | `secret.github-fine-grained-pat` | 90 | `github_pat_` structure, entropy ≥ 3.5 |
| Slack | `secret.slack-token` | 85 | `xox[baprs]-`, entropy ≥ 2.0 |
| Google | `secret.google-api-key` | 80 | `AIza` + 35, entropy ≥ 3.0 |
| Stripe | `secret.stripe-live-key` | 90 | `sk_live_`/`rk_live_`, entropy ≥ 3.0 |
| Stripe | `secret.stripe-test-key` | 30 | below the default threshold by design |
| Anthropic | `secret.anthropic-api-key` | 90 | `sk-ant-api03-`, entropy ≥ 3.5 |
| OpenAI | `secret.openai-api-key` | 85 | `sk-proj-`/`sk-svcacct-`, entropy ≥ 3.5 |
| GitLab | `secret.gitlab-pat` | 85 | `glpat-` + 20, entropy ≥ 3.0 |
| npm | `secret.npm-token` | 85 | `npm_` + 36, entropy ≥ 3.5 |
| SendGrid | `secret.sendgrid-api-key` | 85 | `SG.` structure, entropy ≥ 3.5 |
| Twilio | `secret.twilio-api-key` | 70 | `SK` + 32 hex, entropy ≥ 2.5 |
| Azure | `secret.azure-storage-key` | 85 | `AccountKey=` + 86–90 base64, entropy ≥ 4.0 |
| JWT | `secret.jwt` | 55 | header segment must decode to JSON with `alg` (+10) |
| Generic Secret | `secret.generic-assignment` | 50 | keyword assignment, entropy ≥ 3.2, −10 generic |
| Generic Secret | `secret.generic-high-entropy` | 40 | 40–64 char random string, −10 generic |

Accuracy work behind the table:

- **Entropy is graded, not just gated.** Payloads far above their floor gain 5
  points; payloads within 0.5 bits of it lose 8. Entropy is measured on the
  payload *after* the vendor prefix is stripped, so `sk_live_` cannot depress it.
- **Placeholders are rejected by name**: `example`, `test`, `dummy`, `sample`,
  `fake`, `demo`, `localhost`, `changeme`, `<...>`, and the canonical
  `AKIA…EXAMPLE` key.
- **Comments are filtered**, but conservatively: `https://` is never a comment,
  string literals are skipped, and a miss keeps a finding rather than hiding a
  real credential.
- **One credential, one finding.** A generic match that overlaps a
  provider-specific match is dropped (`superseded`), so the same key is never
  reported twice under different rules.
- **Block formats are shielded.** Base64 key material can never resurface as a
  "high-entropy string", even if the PEM block itself fails validation.
- **Secrets are masked by default**, including inside `Context` — masking only
  the value line would leak the credential anyway.

### js — script triage and endpoint extraction

Scripts on the same registrable domain are fetched; analytics, tag managers and
public CDNs are skipped (they never contain target endpoints). Endpoints are
extracted from quoted literals and absolute URLs, then filtered: asset
extensions, template placeholders (`${…}`, `{{…}}`, `%s`), third-party hosts and
empty paths are dropped, and the rest is normalized and deduplicated.

### param — parameter classification

Curated lists, not heuristics: `high` covers redirect/file/template sinks,
`medium` covers identifiers and content, `noise` covers `utm_*`, `fbclid`,
`gclid` and friends, which are never probed.

### reflect — reflection analysis

Three inert canaries of different length and character class:

```
solix1z9q      soli"x2z'q      soli<x3z>yq
```

They break quotes and tags but contain no event handler, so a probe can never
execute code on the target. A finding requires **two reflected canaries, or the
tag-breaking one intact** — a lone alphanumeric echo is usually an error page
repeating the query, which is exactly the false positive this module avoids.

Scoring: +15 unencoded, +20 in HTML body/attribute, +12 in JavaScript, **−25 in
a comment**, +10 for consistency across canaries, −10 on a 4xx/5xx response,
−15 when the body reads like a generic error page.

### redirect — open redirects

Only redirect-specific parameters are tested, with three payload styles
(`https://`, `//`, `/\`). A finding requires an actual `Location` header
pointing at the canary host — an echoed value is not a redirect, and a relative
redirect is normal application behaviour, not a vulnerability.

### path — sensitive paths

A short, high-value wordlist (`.env`, `.git/config`, `.aws/credentials`,
`id_rsa`, backups, `actuator`, `swagger-ui.html`, …). Only `200`, `401` and
`403` are considered. Soft 404s are filtered against a random baseline with a
size comparison sized relative to the page, default server pages are discarded,
and 200 responses score higher than 403s.

## Infrastructure

- **Polite by default**: a single global token bucket at 10 req/s shared by all
  goroutines, so no module can flood a target.
- **Bounded concurrency**: `internal/errgroup` (a local, dependency-free subset
  of `golang.org/x/sync/errgroup`), 4–8 workers per stage.
- **Classified failures**: DNS, TLS, timeout, connection and invalid-URL errors
  are distinguishable; one dead path never aborts a scan.
- **No redirect following** except for the initial page fetch, so a detection
  never turns into a request to a third party.
- **Request accounting**: the report states how many requests the run actually
  made.

## Known limitations

- No live validation of credentials (no provider API calls); scores are
  structural.
- Reflection detection is single-request, not time-based: stored XSS is out of
  scope.
- Path scanning uses a fixed wordlist capped at 20 entries by default.
- Only `GET` requests are used; form and JSON bodies are not probed.
- Third-party detection uses a small public-suffix table, not the full PSL.
- Low-entropy real tokens are rejected by design; precision beats recall.

## Next steps

1. Stored/blind reflection variants and POST parameter support.
2. Parameter mining from more sources (HTML forms, source maps).
3. Provider-specific live validation behind an explicit flag.
4. Report formats for CI (SARIF).

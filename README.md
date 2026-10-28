# SoliTools

High-accuracy web security scanner in Go, built for penetration testing and bug
bounty work. The guiding rule: **a finding must be worth a human's time**.
Precision beats recall at every decision point, and everything filtered out is
counted and explained rather than silently dropped.

Architecture, maintenance notes, known traps and the design rationale live in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); this file covers usage.

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
solitools tui
```

Two opt-in modes worth knowing up front:

```console
$ solitools scan -crawl -max-pages 5 -wordlist paths.txt https://target.example/
$ solitools scan -forms -stored -rate 50 https://target.example/
$ solitools scan -verify https://target.example/
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
| `-wordlist` | none | custom sensitive-path wordlist (capped at 200 entries) |
| `-forms` | off | submit POST forms (may change state; same-origin only) |
| `-stored` | off | re-fetch known pages to detect stored/blind XSS |
| `-verify` | off | validate supported credentials against provider identity APIs |
| `-crawl` | off | follow same-origin links on the seed page (depth 1) |
| `-max-pages` | 10 | maximum pages fetched when crawling, seed included |
| `-verbose` | off | print the score derivation |
| `-json` | off | machine-readable report |
| `-sarif` | off | SARIF 2.1.0 log for code scanning (excludes `-json`) |
| `-quiet` | off | one-line summary only (CI mode); implies plain output |
| `-width` | 0 | wrap to this many columns; `0` detects the terminal |
| `-color` | `auto` | `auto`, `always` or `never`; `auto` colors only on a terminal |

Authentication is `-header "Authorization: Bearer …"` plus `-cookie`.

### Interactive TUI

`solitools tui` — or a bare `solitools` on a terminal — opens a full-screen
interface over the same engine:

1. **Configure.** Target URL with an editable cursor, checkboxes for crawl,
   forms, stored detection, credential verification, skip-path and masking, a
   confidence radio group (default ≥ 60, strict ≥ 75, all ≥ 0), and numeric
   rate/page limits. `↑/↓` moves, space toggles, `←/→` adjusts, Enter starts,
   `Esc`/`q` exits.
2. **Monitor.** A spinner shows the active stage, with elapsed time, request
   count, measured rate and findings per confidence band. `Esc`/`Ctrl+C`
   cancels the scan and keeps what was found so far.
3. **Explore.** A scrollable list (`↑/↓`, `j`/`k`, `PgUp`/`PgDn`) with severity
   and module badges; the detail panel shows URL, parameter, rule, category,
   value, context and the full score derivation. `m` toggles masking for the
   selected finding, `s` saves a JSON or SARIF report (secrets stay masked on
   disk), `q` exits.

The TUI draws on the alternate screen buffer, so the user's scrollback survives,
and hides the cursor while it owns the terminal. It requires a real terminal on
both stdin and stdout; with a pipe it refuses to start, leaving the plain usage
text and exit code 2 intact. There is no mouse support. If a WAF is detected,
the monitor and explorer headers carry a `[WAF: Provider]` badge.

### Code scanning (SARIF)

`-sarif` emits a SARIF 2.1.0 log for GitHub code scanning and similar viewers.
It and `-json` are mutually exclusive. Mapping decisions, so nobody has to
reverse-engineer them:

- `artifactLocation.uri` is the finding's URL. A `region.startLine` is added
  only for secrets, where the response-body line is known; network findings
  (path, redirect, reflection) carry no region.
- `ruleId` is the stable rule id, with a `rules[]` catalogue carrying
  `security-severity` (critical 9.0, high 7.5, medium-high 5.5, medium 3.5,
  low 1.5) and tags.
- `level`: critical/high → `error`, medium-high → `warning`, medium/low →
  `note`.
- Confidence, band, context, the field list and the signal trace survive in
  `properties`; secrets also carry a `partialFingerprints` entry so a viewer can
  track the same finding across runs.
- Output is never styled and never wrapped.

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
| Private Key | `secret.private-key` | 95 | PEM body must base64-decode to ≥ 64 bytes of DER; raw **or** JSON-escaped newlines |
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
| Azure | `secret.azure-sas-token` | 72 | `sv=<date>` … `sig=`, +8 when scoped by `sp=`/`se=`/`srt=` |
| Discord | `secret.discord-webhook` | 90 | `discord.com/api/webhooks/<id>/<token>`, entropy ≥ 3.0 |
| Telegram | `secret.telegram-bot-token` | 85 | 8–10 digit bot id `:` 35 chars, entropy ≥ 3.5 |
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

### verify — live credential validation

Structural scores answer "does this look like a real key?". `-verify` answers
the next question, for the five providers that expose a harmless read-only
identity endpoint:

| Provider | Rules | Request | Proof of life |
| --- | --- | --- | --- |
| GitHub | `secret.github-token`, `secret.github-fine-grained-pat` | `GET /user`, `Authorization: Bearer`, `User-Agent: solitools` | `login` |
| Slack | `secret.slack-token` | `POST /api/auth.test`, `Authorization: Bearer` | `ok:true`, `user`/`team` |
| GitLab | `secret.gitlab-pat` | `GET /api/v4/user`, `Authorization: Bearer` | `username` |
| OpenAI | `secret.openai-api-key` | `GET /v1/models`, `Authorization: Bearer` | `200` |
| Anthropic | `secret.anthropic-api-key` | `GET /v1/models`, `x-api-key` + `anthropic-version` | `200` |

Outcomes, in confidence terms:

- **Active** — `live-validation +15`, clamped to 100, band `critical`, plus
  `Status: active (<login/username>)`.
- **401/403, or Slack `ok:false`** — `live-validation -30`, plus
  `Status: revoked / invalid`. A key the provider rejects is weaker evidence
  than one it has never seen.
- **Timeout, rate limit, 5xx** — no penalty and no signal; the structural score
  stands and the finding carries `Validation: skipped (<reason>)`.

Safety and cost, since this is the only feature that talks to a third party:

- Strictly opt-in. Without `-verify`, the verifier is never constructed and no
  provider is contacted.
- The scan client is **not** reused: a fresh client with its own timeout sends
  no target headers or cookies, so a target's `Authorization` header cannot
  leak to a provider. Tokens travel in request headers, never URLs, fields or
  error strings.
- Requests are read-only, one per finding, at most four concurrent, with
  redirects disabled and response bodies capped at 1 MiB.
- A provider name can be pointed at another origin through `verify.Verifier`,
  which is how the tests use `httptest` instead of the real APIs.

### waf — firewalls and synthetic blocks

Passive detection needs no extra requests: headers and block-page bodies are
enough. Cloudflare (`cf-ray`, `cf-cache-status`, `Server: cloudflare`),
CloudFront / AWS WAF (`x-amz-cf-id`, `x-amzn-errortype`), Akamai
(`AkamaiGHost`, `X-Akamai-Transformed`), Imperva / Incapsula (`X-Iinfo`,
`X-CDN: Incapsula`) and ModSecurity (`mod_security` markers) are recognised.
A bare 429, or a 403 with no application context, is classed as a generic
block.

What the scanner does with that knowledge:

- **Seed:** a provider is recorded in the result and the report notes that the
target is fronted by it.
- **Probing:** three consecutive block pages (or 429s) raise
  `WAF Interception: Target actively blocked probes (Provider). Findings may be
  suppressed or incomplete.` The witness is a per-response observer scoped to
  the probing stage, so crawler and path requests do not distort it.
- **False-positive guards:** a canary echoed by a WAF block page is not a
  reflection finding, and a synthetic 403 is not a reachable path. Both rules
  key on `IsBlockPage`, never on the mere presence of a WAF: a Cloudflare-
  fronted application still answers normally and is still scanned normally.

The classification is signature-based, so an in-house WAF with a bespoke page
may only surface as a generic block — or not at all.

### js — script triage and endpoint extraction

Scripts on the same registrable domain are fetched; analytics, tag managers and
public CDNs are skipped (they never contain target endpoints). Endpoints are
extracted from quoted literals and absolute URLs, then filtered: asset
extensions, template placeholders (`${…}`, `{{…}}`, `%s`), third-party hosts and
empty paths are dropped, and the rest is normalized and deduplicated.

**Source maps.** A first-party bundle is checked for a trailing
`//# sourceMappingURL` / `/*# sourceMappingURL */` comment and for `SourceMap`
or `X-SourceMap` headers. The map must be same-origin — a CDN map is someone
else's code — and at most five are fetched per run, four at a time, with a
10 MiB cap each. `sourcesContent` is then treated as source: endpoints are
extracted, secrets are scanned with the normal rules, and route bindings are
made concrete (`/users/:id` becomes `/users/1`, with `id` added to the probe
pool). This is often where the unminified API surface lives.

### param — parameter classification

Curated lists, not heuristics: `high` covers redirect/file/template sinks,
`medium` covers identifiers and content, `noise` covers `utm_*`, `fbclid`,
`gclid` and friends, which are never probed.

**JSON mining.** A page, crawled API response or probe answer that is JSON (by
`Content-Type`, or a body starting with `{`/`[`) is walked up to three levels
deep. Only keys classified high or medium — `redirect`, `next`, `callback`,
`path`, `id`, … — join the parameter pool; low-interest fields and tracking
noise do not. Names found in a probe response arrive after the parameter
snapshot, so they are probed in one bounded second pass (five targets) and are
never recursed.

### form — parameters that never appear in a URL

A URL-only scanner sees nothing of a form. `internal/form` parses `<form>`
markup for its action, method and named controls, resolving relative actions and
dropping anything unusable (unclosed forms, `mailto:` actions, unknown verbs).

- **GET forms** are folded into the query path: their action plus default values
  is just a URL, so they cost one request and change nothing.
- **POST forms** are only submitted with `-forms`, and only when the action is
  on the target host. Forms with a file input are skipped (a body cannot be
  reconstructed from markup), and forms that look destructive — `delete`,
  `checkout`, `payment`, `transfer`, … in the action or a field name — are
  skipped too. A submission can create records or send mail; opt-in is the only
  honest default.
- Every other field keeps its original value, so CSRF tokens and framework state
  (`__VIEWSTATE`, `_token`, `csrfmiddlewaretoken`) are submitted untouched and
  never replaced by a canary.

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

`-stored` adds a second pass with a different question. After probing, the scan
re-fetches each page that received a canary (one GET per page, capped at five)
and looks for values the server kept. Only canaries **absent from the immediate
response** qualify — an echoed value is reflection and is already reported — so
the same evidence can never produce both findings. The page is fetched with the
probed parameter removed, so the re-fetch cannot echo the canary by itself.

Scoring: 65 base, +20 HTML body/attribute, +12 JavaScript, **−25 comment**, +10
when several canaries persisted, −10 generic error page. The same arithmetic
applies (two canaries, or the tag-breaking one), which rejects a stored but
HTML-escaped copy. Detection is same-origin and limited to pages the scan
already knows: there is no out-of-band listener, so a value that only surfaces
in an admin panel stays invisible.

**JSON APIs.** A parameter on an `/api/` route, or one mined from JSON or a
source map, is also probed with a JSON body — `{"name":"<canary>"}`, nested at
the mined path (`{"filter":{"url":…}}`). The request sets
`Content-Type: application/json; charset=utf-8` and
`Accept: application/json, text/plain, */*`. A JSON echo is classified as
`JSON body`; an API error page rendered as HTML is scored like any HTML
reflection. Findings carry `Method: POST (JSON)` and rule id `reflect.json`, so
a query finding on the same URL is not collapsed into it. WAF block pages are
ignored exactly as on GET.

### redirect — open redirects

Only redirect-specific parameters are tested, with five payload styles
(`https://`, `//`, and the backslash forms `/\`, `\/`, `\\`). A finding requires
an actual `Location` header pointing at the canary host — an echoed value is not
a redirect, and a relative redirect is normal application behaviour, not a
vulnerability. Backslashes are folded to slashes before analysis, because
browsers do the same everywhere in a special-scheme URL: a filter that only
blocks `//` does not hide the finding, and `//host[backslash]path` is still
recognised even though Go's parser rejects it on its own.

**JSON APIs.** Redirect-capable parameters on API or mined endpoints are also
sent as `{"<name>":"https://example.com/solitools-redirect-check"}` with a JSON
body. The same `Location` verification applies, findings carry
`Method: POST (JSON)` and rule id `redirect.json`, and a WAF block page is
ignored before the redirect is examined.

### path — sensitive paths

A short, high-value wordlist (`.env`, `.git/config`, `.aws/credentials`,
`id_rsa`, backups, `actuator`, `swagger-ui.html`, …). Only `200`, `401` and
`403` are considered. Soft 404s are filtered against a random baseline with a
size comparison sized relative to the page, default server pages are discarded,
and 200 responses score higher than 403s.

`-wordlist` replaces that list with a file: one path per line, blank lines and
`#` comments ignored, duplicates dropped, leading slashes trimmed. It is capped
at 200 entries and a truncation warning is reported, because a scanner that
probes thousands of paths has stopped being surgical. A custom list is used in
full; the default 20-entry budget applies only to the built-in list.

### crawl — same-origin pages

`-crawl` follows `<a href>` links found on the seed page, one level deep and
never further. `-max-pages` (default 10) counts every page in the run, seed
included, and each fetch passes through the shared rate limiter at concurrency
4.

Candidates must match the seed's scheme, host and port exactly; a link that
changes any of the three is ignored, as are `mailto:`, `javascript:`, `tel:` and
fragment-only links. Asset extensions (`.css`, `.js`, images, fonts, `.pdf`,
`.zip`, video) and session-ending or destructive paths (`logout`, `signout`,
`deactivate`, `delete-account`) are never fetched. Fragments and redundant
trailing slashes are normalised before deduplication, so one page is fetched
once.

Each crawled page then goes through the same treatment as the seed: secret
scanning, endpoint and parameter extraction, first-party script analysis, and
form discovery (GET forms always; POST forms only with `-forms`). With
`-stored`, crawled pages also become observation targets, which is how a value
stored by a form on one page is found on a listing page.

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

- Credential scores are structural by default. `-verify` checks only GitHub,
  Slack, GitLab, OpenAI and Anthropic, only whether the credential is active,
  and not what it is allowed to do.
- WAF detection is signature-based. An unknown or custom firewall may be
  misclassified as a generic block, and the generic 403 heuristic deliberately
  ignores plain "Forbidden" pages to avoid hiding real findings.
- Reflection detection is single-shot on the page itself. With `-stored` the
  scan re-fetches known pages once, later in the run; truly blind XSS needs an
  out-of-band listener and is out of scope.
- Path scanning uses the built-in 26-entry wordlist (first 20 by default), or
a custom file capped at 200 entries.
- `GET` is the default; bodies are submitted only for POST forms behind
  `-forms`. JSON bodies are never sent.
- Crawling is depth one, opt-in and capped at 10 pages including the seed.
- Third-party detection uses a small public-suffix table, not the full PSL.
- Low-entropy real tokens are rejected by design; precision beats recall.
- Mining is bounded: five source maps per run at 10 MiB each, JSON depth three,
  and five second-pass parameters. A map behind a CDN or in a non-standard
  format is skipped rather than guessed at.
- JSON probing covers `/api/` routes and parameters mined from JSON or source
  maps. Only one body shape is tried per parameter (the mined path), so a schema
  that insists on sibling fields may reject the probe.

## Next steps

1. Authenticated scanning from a session file (cookies beyond `-cookie`).
2. DOM XSS analysis of the bundles already fetched.

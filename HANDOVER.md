# SoliTools — Handover for the next agent

**Status:** working, tested, committed. Nothing is half-finished or uncommitted.
**Version:** `0.7.0` · **Branch:** `main` · **Commits:** 8
**Size:** 46 Go files, ~6,800 lines, 129 test functions, 21 secret rules, zero external dependencies.
**Last verified:** `gofmt` clean · `go vet` clean · `go test -count=1 ./...` all green · cross-compiles for `linux` and `darwin`.

Latest commits: run `git log --oneline -6`. Hashes age; the invariants below do not.

This document is written so you can pick up cold: what exists, why it is built
this way, what will bite you, and what to do next. Read §3 (the traps) before
changing anything — it will save you hours.

---

## 1. What this is

A command-line web security scanner for **authorized** penetration testing and
bug bounty work. You give it a URL; it fetches the page, triages its JavaScript,
extracts endpoints and parameters, probes them for reflection and open
redirects, checks a short list of sensitive paths, and prints findings with an
explainable 0–100 confidence score.

The product thesis is unusual and drives almost every implementation choice:

> **A finding must be worth a human's time. Precision beats recall, always.**

That is why there is a confidence model, why rules gate on structure rather
than keyword matching, why suppressed items are always counted, and why the
default threshold (60) hides half of what the tool actually detects.

```
solitools scan https://target.example/
```

Safety posture, do not regress it:

- No network call ever goes anywhere except the target. The redirect module
  reads a `Location` header; it never follows it.
- The reflection canaries are inert (`solix1z9q`, `soli"x2z'q`, `soli<x3z>yq`):
  they break quotes and tags but contain no handler and no script.
- One global token bucket (10 req/s default) shared by every module.
- A `GET`-only tool today; no form or JSON body is ever submitted.

---

## 2. Build, run, verify

```console
go build -o solitools ./cmd/solitools
./solitools scan -rate 50 https://target.example/
```

### 2.1 This machine has a Go environment quirk — read this

`LOCALAPPDATA` is empty in this environment, so Go reports `GOCACHE=off` and
**every** `go` command fails with:

```
build cache is required, but could not be located: GOCACHE is not defined
```

Always prefix Go commands with a cache path:

```powershell
$env:GOCACHE="$env:TEMP\solitools-gocache"
go test ./...
```

Do not "fix" this by editing the user's environment permanently; set it per
shell. A build that silently failed and then ran a stale `solitools.exe` has
already happened once here.

### 2.2 Verification gate (run before every commit)

```powershell
$env:GOCACHE="$env:TEMP\solitools-gocache"
gofmt -l .          # must print nothing
go vet ./...        # must be silent
go test -count=1 ./...
```

`./internal/secret` generates a fresh RSA key in one test, so run
`go test ./internal/secret -count=10` when you touch key material, comment
detection, or gates: some failures only appear for certain random keys.

### 2.3 Git

- Repo-local identity: `Soliofski <Soliofski@users.noreply.github.com>`.
- **No remote is configured.** Nothing has been pushed.
- Commit style: `feat: …`, `feat(ui): …`, with a body explaining *why*.
- The tree must stay clean; `.gitignore` already excludes `solitools.exe`.

### 2.4 CLI reference

| Flag | Default | Meaning |
|------|---------|---------|
| `-strict` | off | only show findings with confidence ≥ 75 |
| `-all` | off | show everything, including low confidence |
| `-min-score` | unset | explicit threshold; overrides `-strict` / `-all` |
| `-mask` | **true** | mask secret values (`-mask=false` reveals them) |
| `-rate` | 10 | max requests per second, shared by all stages |
| `-proxy` | none | HTTP / HTTPS / SOCKS5 proxy URL |
| `-header` | none | extra header, `"Name: value"`, repeatable |
| `-cookie` | none | raw `Cookie` header value |
| `-timeout` | 15s | per-request timeout, body included |
| `-max-params` | 10 | parameters actively probed |
| `-skip-path` | off | skip the sensitive-path wordlist |
| `-verbose` | off | print the score derivation and signals |
| `-quiet` | off | one-line summary only; implies plain output |
| `-width` | 0 | wrap to N columns; `0` detects the terminal |
| `-color` | auto | `auto`, `always` or `never` |
| `-json` | off | machine-readable report |
| `-sarif` | off | SARIF 2.1.0 log; mutually exclusive with `-json` |

Exit codes: `0` nothing at the selected threshold, `1` findings reported,
`2` usage or runtime error. `-json` never contains ANSI, never wraps, and
skips the banner.

```console
$ solitools scan -quiet -rate 50 https://target.example/
4 findings · 30 requests · 3 critical, 1 high
```

```json
{
  "version": "0.4.0",
  "target": "https://target.example/?q=1",
  "threshold": 60,
  "findings": [
    {
      "kind": "SECRET",
      "category": "GitHub",
      "rule_id": "secret.github-token",
      "title": "GitHub Token",
      "url": "https://target.example/app.js",
      "value": "ghp_********************************Ge3N",
      "context": "...var t = \"ghp_********************************Ge3N\";...",
      "fingerprint": "8a54e08d284607d3",
      "confidence": { "base": 90, "value": 95, "band": "critical" }
    }
  ],
  "stats": { "requests": 30, "pages": 1, "scripts": 1, "endpoints": 1, "parameters": 2 }
}
```

---

## 3. Traps that cost time here (read first)

| # | Trap | What actually happens | What to do |
|---|------|----------------------|------------|
| 1 | `GOCACHE` unset | `go build` fails, the old binary runs, output looks stale | Always set the cache; check `$LASTEXITCODE` after `go build` |
| 2 | Windows file locks | `go test ./...` randomly fails with `report.test.exe: The process cannot access the file` | Transient antivirus/indexer lock; wait ~1s and re-run. It is **not** a test failure |
| 3 | PowerShell mangles ANSI | `Out-String` turns `ESC` into the literal text `\u001b[...]`, so colour looks broken and regex stripping fails | Verify terminal output through Python `subprocess` + `re`, not PowerShell strings |
| 4 | The Read tool redacts secret-like lines | A Go line such as `"secret": "1;38;5;213"` can come back as `[redacted]`, and an edit against that text fails | The file is fine. Compile to confirm; never "repair" based on a redacted read |
| 5 | Base64 contains `//` and `/*` | A PEM body can look like a comment; the key disappears intermittently | Block spans are shielded from comment scanning (`shieldSpans`, `insideAny`). Keep that |
| 6 | Random key material contains `test`/`demo` | Placeholder heuristics reject a real private key | Encoded payloads (rules with `ShieldGeneric`) skip text heuristics entirely |
| 7 | Same credential reported twice | `secret.generic-assignment` matches what a vendor rule already matched | Generic candidates overlapping a specific span are dropped as `superseded` |
| 8 | Masking leaks through `Context` | `-mask` used to replace only `Value`; the raw secret stayed in the snippet | `report.Render` rewrites the context with the masked value. Keep both paths |
| 9 | Box borders drift | Widths measured in **bytes**; `·` is 2 bytes but 1 column | All box geometry uses `runeLen` |
| 10 | Animation corrupts redirected output | `-color=always \| file` would write `\r` and clear-line codes | Animation requires a real TTY (`term.IsTerminal`), independent of colour mode |
| 11 | URLs get hard-wrapped | A split URL cannot be copied into a browser | `URL` rows are exempt from wrapping |
| 12 | Soft-404 filter too loose | A 512-byte absolute tolerance treats any tiny page as the catch-all | `similarSize` is relative with a 200-byte scale floor |

---

## 4. Architecture

```
cmd/solitools      flags, banner, exit codes, wiring
internal/scan      orchestrator: one target, six modules, dedupe
internal/httpx     the only place that performs I/O; rate limit, proxy, errors
internal/errgroup  local subset of x/sync/errgroup (no external deps)
internal/finding   shared result type; no printing
internal/confidence scoring model: base + signals, clamp, band
internal/secret    credential detection
internal/js        script triage + endpoint extraction
internal/form      HTML form parsing, safety classification
internal/param     parameter classification
internal/reflect   reflected-input canaries
internal/redirect  open redirect verification
internal/pathscan  sensitive path probing
internal/report    text / JSON / quiet rendering, masking
internal/term      palette, TTY detection, width detection
internal/progress  one-line live status during a scan
```

```mermaid
flowchart LR
    CLI["cmd/solitools<br/>flags, banner, exit codes"]
    SCAN["internal/scan<br/>orchestrator"]
    REPORT["internal/report<br/>text, JSON, quiet"]
    TERM["internal/term<br/>palette, TTY, width"]
    PROG["internal/progress<br/>live status line"]

    SECRET["internal/secret"]
    JS["internal/js"]
    FORM["internal/form"]
    PARAM["internal/param"]
    REFLECT["internal/reflect"]
    REDIRECT["internal/redirect"]
    PATH["internal/pathscan"]

    HTTP["internal/httpx<br/>rate limit, proxy, error classes"]
    EG["internal/errgroup"]
    CONF["internal/confidence"]
    FIND["internal/finding"]

    CLI --> SCAN
    CLI --> REPORT
    CLI --> TERM
    CLI --> PROG
    SCAN --> SECRET
    SCAN --> JS
    SCAN --> FORM
    SCAN --> PARAM
    SCAN --> REFLECT
    SCAN --> REDIRECT
    SCAN --> PATH
    SCAN --> HTTP
    SCAN --> EG
    SCAN --> FIND
    SECRET --> CONF
    SECRET --> FIND
    REFLECT --> CONF
    REDIRECT --> CONF
    PATH --> CONF
    REPORT --> FIND
    REPORT --> TERM
    PROG --> TERM
    PROG --> HTTP
```

**Layering rules that keep this maintainable**

1. Only `internal/httpx` performs network I/O. Modules receive `*httpx.Client`.
2. Only `internal/report` prints. Modules return `[]finding.Finding`.
3. `finding` imports `confidence`; nothing else in the model layer imports up.
4. No module knows about another module; `scan` is the only integrator.
5. No external dependencies. `errgroup` was written locally for that reason —
   keep it that way unless the user explicitly asks for a dependency.

### 4.1 Repository layout

```
.
├── README.md                  product docs, rule table, limitations
├── HANDOVER.md                this document
├── go.mod                     module solitools, go 1.21
├── .gitignore                 /solitools, /solitools.exe, editor noise
├── cmd/solitools/
│   ├── main.go                flags, banner, wiring, exit codes
│   └── main_test.go           13 CLI tests against httptest servers
└── internal/
    ├── confidence/            scoring model
    ├── errgroup/              local x/sync subset
    ├── finding/               shared Finding type
    ├── form/                  form parsing, safety classification
    ├── httpx/                 the only I/O
    ├── js/                    script triage, endpoint extraction
    ├── param/                 parameter classification
    ├── pathscan/              wordlist probing, soft-404
    ├── progress/              live status line
    ├── redirect/              open redirect verification
    ├── reflect/               reflection canaries
    ├── report/                text, JSON, quiet, masking
    ├── scan/                  orchestrator + dedupe
    ├── secret/                rules, scanner, comments, context, entropy
    └── term/                  palette, TTY, width (windows + unix build tags)
```

`internal/term` is the only package with build-tagged files:
`term_windows.go` / `width_windows.go` for the console API,
`width_unix.go` for `TIOCGWINSZ`, `width_other.go` for everything else.

> There is a stray `solitools` (Linux ELF) in the repo root from a
> `GOOS=linux go build ./...` verification. It is gitignored and safe to delete;
> the Windows binary is `solitools.exe`, also ignored.

---

## 5. The scan pipeline

```mermaid
flowchart TD
    START(["solitools scan URL"]) --> FETCH["httpx.Fetch<br/>follow up to 5 redirects"]
    FETCH --> PAGE["secret.Scan<br/>page body"]
    PAGE --> SCRIPTS["js.ScriptURLs<br/>drop third-party hosts"]
    SCRIPTS --> FETCHJS["fetch up to 10 first-party bundles<br/>4 concurrent"]
    FETCHJS --> SEC2["secret.Scan<br/>each bundle"]
    FETCHJS --> ENDP["js.ExtractEndpoints"]
    ENDP --> PARAMS["param.Names<br/>drops utm_ and fbclid"]
    PARAMS --> PROBE["probe up to 10 parameters<br/>reflect + redirect"]
    PROBE --> PATHS["pathscan<br/>20 of 26 words"]
    PATHS --> DEDUPE["dedupe + sort by confidence"]
    DEDUPE --> OUT(["scan.Result"])
```

### 5.1 One run, end to end

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant CLI as cmd/solitools
    participant H as httpx
    participant S as scan.Run
    participant M as modules
    participant R as report

    U->>CLI: solitools scan URL
    CLI->>CLI: parse flags, build theme
    CLI->>H: New rate, proxy, headers, cookie
    CLI->>S: Run with Progress callback
    S->>H: Fetch target page
    H-->>S: status, headers, body
    S->>M: secret.Scan page body
    S->>H: fetch first-party scripts
    S->>M: secret.Scan and js.ExtractEndpoints per bundle
    S->>M: reflect and redirect probes per parameter
    S->>M: pathscan over the wordlist
    M-->>S: candidate findings
    S->>S: dedupe, sort, count
    S-->>CLI: Result and Stats
    CLI->>R: Render threshold, mask, theme, width
    R-->>U: findings, summary, exit code
```

### 5.2 Concurrency and politeness

```mermaid
flowchart LR
    subgraph stages["Stages run in sequence, each internally parallel"]
        A["scripts<br/>limit 4"]
        B["probes<br/>limit 4"]
        C["paths<br/>limit 6"]
    end
    A --> B
    B --> C
    A --> L
    B --> L
    C --> L
    subgraph gate["httpx"]
        L["global token bucket<br/>default 10 req/s"]
        L --> REQ["one HTTP request"]
    end
```

Consequences to preserve:

- Every request, from every module, passes the same bucket. No module can
  starve another or exceed `-rate`.
- Concurrency limits are per stage, so a slow target degrades throughput, not
  correctness.
- A failed request is classified (`dns`, `tls`, `timeout`, `connection`,
  `invalid-url`) and skipped; one dead path never aborts a scan.
- `Client.Requests()` is an atomic counter; the report states the real cost of
  a run.

---

## 6. The confidence model

`internal/confidence` is deliberately tiny and deterministic: no model, no
randomness, no learning. Same bytes in, same score out, every time.

| Band | Range | Meaning | Visible at |
|------|-------|---------|-----------|
| `critical` | 90–100 | vendor-identified, structurally valid, or protocol-verified | default |
| `high` | 75–89 | likely real | default |
| `medium-high` | 60–74 | product default threshold | default |
| `medium` | 40–59 | needs `--all` | only `-all` |
| `low` | < 40 | usually noise | only `-all` |

```mermaid
flowchart LR
    BASE["rule base<br/>30 to 95"] --> GATES{"hard gates pass?"}
    GATES -->|"no"| DROP["suppressed<br/>counted by reason"]
    GATES -->|"yes"| SIG["signals<br/>entropy plus or minus<br/>generic penalty"]
    SIG --> CLAMP["clamp 0 to 100<br/>round to 0.1"]
    CLAMP --> BAND["band lookup"]
    BAND --> THRESH{"score at or above threshold?"}
    THRESH -->|"no"| HIDDEN["hidden<br/>counted as below threshold"]
    THRESH -->|"yes"| SHOW["reported"]
```

### 6.1 Gates versus signals — the central distinction

- **Gates** reject a candidate outright. A malformed value is not a weak
  finding, it is not a finding. Gates never produce a score.
- **Signals** adjust confidence and are always recorded in
  `Finding.Confidence.Signals`, with a name, a delta and a human reason.

Why it matters: if you lower a score to express doubt, you create findings that
"look real but score low" and nobody knows why. If you gate, the reason is
recorded in `Stats.ByReason` and the candidate never reaches the report.

Current signals:

| Signal | Delta | When |
|--------|-------|------|
| `entropy` | +5 | payload ≥ floor + 1.5 bits/symbol |
| `entropy` | −8 | payload < floor + 0.5 bits/symbol |
| `generic-rule` | −10 | rule matches a shape, not a provider |
| `structural` | +10 | JWT header decodes and names an algorithm |
| `path-context` | −20 / −10 | *removed* — see note below |

> Note: `path-context` existed in the file-scanner era. The URL-based tool has
> no filesystem path to inspect, so it was deleted along with the file walker.
> Do not resurrect it without a URL-specific rationale.

### 6.2 Threshold resolution (CLI)

```
explicit -min-score   wins
-strict               75
-all                  0
default               60
```

`-strict` and `-all` together is an error (a typo must not silently pick one).
`-min-score` outside `[0, 100]` is an error.

---

## 7. Data model

`internal/finding.Finding` is data-only. Detectors fill it; `report` renders it.

| Field | Meaning |
|-------|---------|
| `Kind` | `SECRET`, `REFLECT`, `REDIRECT`, `PATH` — the badge in the report |
| `Category` | provider or class: `AWS`, `GitHub`, `JWT`, `Open Redirect`, `Sensitive Path` |
| `RuleID` | stable machine id, e.g. `secret.github-token` |
| `Title` | human headline, e.g. `GitHub Token` |
| `URL` | where the evidence came from |
| `Value` | the matched secret or the payload that triggered the finding |
| `Context` | short snippet around the evidence, whitespace collapsed |
| `Fingerprint` | first 16 hex of SHA-256 over the whitespace-stripped payload |
| `Fields` | ordered detail lines (`Line`, `Entropy`, `Parameter`, `Status`, …) |
| `Confidence` | base, value, band and the full signal trace |

**Deduplication identity** (`Finding.DedupeKey`):

- Secrets → `kind|rule|fingerprint`. The same key found on ten pages is one
  finding; `scan.dedupe` appends an `Occurrences` field.
- Everything else → `kind|rule|URL`. Two payloads at the same URL are the same
  result.

`Confidence.Score` is also data: `Base`, `Value`, `Band`, `Signals[]`. It
serialises into JSON as-is, which is what makes a report auditable.

---

## 8. Modules

### 8.1 `secret` — the accuracy-critical one

Entry point: `secret.New()` then `Scanner.Scan(Document{Source, Body})`.
21 rules live in `internal/secret/rules.go`; the engine is `scanner.go`.

```mermaid
flowchart TD
    M["regex match"] --> G["take capture group"]
    G --> P["strip vendor prefix"]
    P --> CHK{"length, placeholder,<br/>padding, entropy floor,<br/>structural decode"}
    CHK -->|"fail"| X1["gated<br/>counted by reason"]
    CHK -->|"pass"| CM{"inside a comment?"}
    CM -->|"yes"| X2["gated as comment"]
    CM -->|"no"| SC["score equals base plus signals"]
    SC --> OV{"generic rule, and overlaps<br/>a provider match?"}
    OV -->|"yes"| X3["gated as superseded"]
    OV -->|"no"| K["finding<br/>context, fingerprint, trace"]
```

Rules worth understanding before you touch them:

PEM detection accepts a raw block and the JSON-escaped form
(`"----BEGIN…\n…----"`): the body class allows a backslash, `requirePEMBlock`
strips `\n`/`\r`/`\t` before decoding, and `blockHeader` cuts the reported value
at either a real or an escaped newline so the body never reaches a report.
Azure SAS is the context-dependent one: a bare `?sig=` is meaningless, so the
pattern demands the `sv=<date>` stamp first, and `Validate` adds confidence when
`sp=`/`se=`/`srt=` show the signature is scoped.

| Rule | Base | Why it is safe from false positives |
|------|------|-------------------------------------|
| `secret.private-key` | 95 | body must base64-decode to ≥ 64 bytes of DER; header/footer must match |
| `secret.aws-access-key-id` | 85 | reserved 4-char prefix + exactly 16 uppercase alphanumerics |
| `secret.github-token` | 90 | `ghp_`-style prefix + exactly 36 characters |
| `secret.stripe-live-key` | 90 | `sk_live_` / `rk_live_` + 24–247 alphanumerics |
| `secret.azure-sas-token` | 72 | needs `sv=<date>` before the `sig=` it captures; +8 when `sp=`/`se=`/`srt=` prove the scope |
| `secret.discord-webhook` | 90 | fixed host + 17–20 digit id + 60–80 char token |
| `secret.telegram-bot-token` | 85 | 8–10 digit id, colon, exactly 35 characters |
| `secret.jwt` | 55 | header segment must decode to JSON with `alg` (adds +10) |
| `secret.generic-assignment` | 50 | keyword assignment; −10 generic keeps it at 40, below the threshold |
| `secret.generic-high-entropy` | 40 | bare random string; −10 generic → 30, effectively opt-in via `-all` |

Invariants:

1. A rule must encode **provider identity**, not a keyword plus entropy.
2. Generic rules must never reach 60 on their own — `TestGenericRulesStayBelowDefaultThreshold`
   enforces the arithmetic for you.
3. Encoded payloads (`ShieldGeneric`) skip placeholder and repetition checks:
   random base64 legitimately contains `test`, `demo`, and even `//`.
4. A PEM `Value` is only ever the header line. The body never enters a report,
   masked or not.

### 8.2 `js` — script triage and endpoints

- `ScriptURLs(html, base)` resolves `src` values, dedupes, keeps order.
- `IsThirdParty(asset, base)` compares registrable domains (small public-suffix
  table, not the full PSL) plus an explicit CDN/analytics list.
- `ExtractEndpoints(js, base)` only accepts literals that start with `/`
  (otherwise a quoted token becomes an "endpoint"), drops asset extensions
  including `.js`, drops template placeholders (`${`, `{{`, `<%`, `%s`), and
  rejects cross-site hosts.

Deliberate omissions: inline `<script>` bodies are **not** scanned separately —
the page body already contains them, and scanning both double-counted secrets.

### 8.3 `param` — classification

Curated lists, not heuristics. `High` (redirect, file, template sinks),
`Medium` (identifiers, content), `Noise` (`utm_*`, `fbclid`, `gclid`, …).
`Names()` returns query parameters in document order, deduped, noise removed.
Only `Noise` is filtered; the rest are ranked by interest in `scan`.

### 8.4 `reflect` — proof of reflection

Three canaries, and a finding needs **two of them, or the tag-breaking one
intact**. That rule exists because a single alphanumeric echo is usually a
search page or a 404 repeating the query — the classic false positive.

Scoring: base 45, +15 unencoded, +20 HTML body/attribute, +12 JavaScript,
**−25 comment**, +10 consistency, −10 error status, −15 generic error page.

`Classify(body, offset)` distinguishes comment, inside-tag (attribute),
script, JSON and plain text. It is the most testable part; use it directly.

### 8.5 `redirect` — verification, not reflection

Only redirect-specific parameter names are probed (`IsRedirectParam`). Three
payload styles (`https://`, `//`, `/\`) point at `example.com`, which is
reserved by RFC 2606 and never contacted — only the `Location` header is read.
A relative redirect is normal behaviour and is never reported.

`normalizeLocation` handles the backslash family: browsers read `\` as `/` in
the authority position, so `/\host`, `\/host` and `\\host` are all `//host`.
Without that normalisation, a server that echoes the backslash payload produces
a `Location` Go parses as a relative path with an empty host, and the module
silently misses a real open redirect. A **single** leading slash must stay a
path — normalising it would make every internal redirect look external — and a
UNC-style `\\server\share` path must still fail to parse as a host. Both cases
are pinned in `TestLeavesSite`.

### 8.7 `form` — parameters hidden in markup

Entry point: `form.Parse(html, base) []Form`, then `Form.Values()` and
`Form.ProbeFields()`.

A URL-only scanner never sees a form field. The parser extracts `<form>` blocks
with a regex, resolves the action against the page URL (dropping `mailto:` and
`javascript:` actions), and collects `input`, `select` and `textarea` names.
Unclosed forms are skipped: guessing where a form ends risks attributing another
form's fields to it.

Three classes of field exist:

| Class | Behaviour |
|-------|-----------|
| probeable | replaced by a canary during probing |
| CSRF / nonce / framework state (`_token`, `csrfmiddlewaretoken`, `__VIEWSTATE`, `_method`, `state`, anything with a `__` prefix) | submitted with its original value, never replaced |
| submit, button, reset, image | dropped entirely — they carry no parameter |

How forms enter the pipeline (`scan.collector.addForms`):

- **GET forms** are folded into the query path: action plus default values is
  just a URL, so they reuse the existing GET probe machinery and change nothing.
- **POST forms** require `-forms`, an action on the same host, no file input
  (a multipart body cannot be reconstructed from markup) and a non-destructive
  shape (`LooksDestructive` looks for `delete`, `checkout`, `payment`,
  `transfer`, … in the action path or a field name). `MaxForms` defaults to 3.

`httpx.PostForm` is the only state-changing call in the codebase. Every other
request is a GET. If you extend the tool, keep that property: a POST must always
be traceable to an explicit user decision.

26 entries (`.env`, `.git/config`, `.aws/credentials`, `id_rsa`, backups,
`actuator`, `swagger-ui.html`, …), capped at 20 per run. Only `200`, `401`,
`403` count. A random baseline detects catch-all hosts by comparing body size
relative to the page (with a 200-byte scale floor). Default server pages are
discarded. `200` outranks `403`.

---

## 9. Rendering

`internal/report.Render` is the only printer. Decision order:

```mermaid
flowchart TD
    R["Render"] --> F["filter by threshold"]
    F --> J{"JSON?"}
    J -->|"yes"| JSON["machine output<br/>no colour, no wrapping, no banner"]
    J -->|"no"| S{"SARIF?"}
    S -->|"yes"| LOG["SARIF 2.1.0<br/>URL as artifact, line when known"]
    S -->|"no"| Q{"quiet?"}
    Q -->|"yes"| ONE["one line<br/>findings, requests, bands, hidden"]
    Q -->|"no"| T{"theme enabled?"}
    T -->|"no"| PLAIN["plain text<br/>wrapped only if width is known"]
    T -->|"yes"| RICH["badges, bands, box<br/>wrapped to terminal width"]
```

Rules that must survive future edits:

1. **Masking happens before rendering**, and it rewrites `Context` as well as
   `Value`. Masked output must never contain the raw secret anywhere.
2. **JSON and SARIF are never styled and never wrapped.** `SetEscapeHTML(false)` is
   deliberate: `&` must not become `\u0026` inside URLs. SARIF is file-oriented,
   so a finding's URL becomes the artifact URI and only secrets carry a
   `region.startLine`; never invent a line for network findings.
3. **Colour needs evidence**: a real terminal, no `NO_COLOR`, no
   `CLICOLOR=0`, no `TERM=dumb`, and a successful VT-mode switch on Windows.
4. **Animation needs a real TTY**, separately from colour.
5. **Wrapping is content-aware**: words stay whole, long tokens split at a path
   separator, HTML tags are never cut in half, and `URL` rows are exempt.
6. **Everything suppressed is counted** — `Stats.ByReason` and the
   "below threshold" count. No silent filtering.

---

## 10. Testing

129 test functions. The distribution matters more than the number:

| Package | Focus |
|---------|-------|
| `secret` (21) | every rule positive, plus explicit false-positive regressions |
| `report` (16) | masking in context, JSON purity, SARIF mapping, wrapping limits, quiet |
| `term` (11) | mode precedence, palette mapping, width parsing |
| `cmd` (14) | exit codes, flags, JSON schema, quiet, colour, form opt-in |
| `form` (10) | action resolution, field classes, destructive detection |
| `httpx` (7) | POST body, redirect policy, header injection, error classes |
| `js` (6) | script resolution, third-party, endpoint filtering |
| `param` (4) | classification, noise removal |
| `reflect` (5) | context classification, POST bodies, escaped reflection rejected |
| `redirect` (7) | external verified, internal ignored, echo ignored, backslash forms |
| `pathscan` (3) | status filter, soft-404, catch-all host |
| `scan` (6) | full pipeline, form opt-in, cross-origin rejection |
| `confidence` (10) | bands, clamping, rounding, NaN, trace immutability |
| `progress` (6) | render format, silence without a TTY, concurrency safety |

Test doubles are `httptest.NewServer` — no network, no fixtures on disk. The
pipeline test (`internal/scan/scan_test.go`) serves a page with a token, a
bundle with an endpoint, a reflected parameter, a redirect parameter and a
`.env`, then asserts all five results and the `Occurrences` dedupe count.

**When you add a detector test, add the false positive first.** The FP cases are
the specification: `AKIAIOSFODNN7EXAMPLE`, padded tokens, Stripe test keys,
`password = "changeme"`, escaped reflections, internal redirects, catch-all
hosts.

---

## 11. Invariants — do not break these

| Invariant | Guarded by |
|-----------|-----------|
| Masked output never contains the raw secret, including in `Context` | `TestMaskCoversContextToo` |
| JSON contains no ANSI and no HTML escaping | `TestJSONNeverContainsEscapes`, `TestJSONIsNeverStyled` |
| Generic rules cannot reach the default threshold alone | `TestGenericRulesStayBelowDefaultThreshold` |
| One credential yields one finding | vendor table + `TestRunEndToEnd` occurrences |
| A reflection needs 2 canaries or the tag canary | `TestProbeRejectsEscapedReflection` |
| An open redirect needs an external `Location` | `TestProbeIgnoresInternalRedirect` |
| A catch-all host yields no path findings | `TestProbeSkipsCatchAllHosts` |
| Scores are deterministic and clamped | `internal/confidence` tests |
| Piped text output has no escapes and no wrapping | `TestPlainReportHasNoEscapes`, `TestNoWrappingWithoutWidth` |
| Exit codes: 0 clean, 1 findings, 2 error | `cmd` tests |

---

## 12. Recipes

### Add a secret rule

1. Append to `Rules()` in `internal/secret/rules.go` with `ID` (`secret.`-prefixed),
   `Title`, `Category`, `Base`, `Pattern`, `Group`, `Prefixes`, `MinLen`/`MaxLen`,
   `EntropyMin`.
2. Prefer a reserved prefix or a structural check. If you need to accept a
   shape, set `Generic: true` so the −10 applies.
3. Add a positive case to `TestVendorTokenRules`.
4. Add a false-positive case to `TestHardSuppression` or the FP table.
5. Run `go test ./internal/secret -count=10`.

### Add a module

1. New package under `internal/`, depending only on `httpx`, `finding`,
   `confidence` and pure stdlib.
2. Expose `Probe(ctx, target) (finding.Finding, bool)` or the idiomatic
   equivalent; **never print**.
3. Cap the work (max requests) and let the shared client enforce rate.
4. Wire into `scan.Run` as a stage: call `options.reportProgress("…")`, use
   `errgroup` with a limit, collect through `collector.addFinding`.
5. Test the pure logic directly; test the network path with `httptest`.

### Add a CLI flag

`cmd/solitools/main.go` (flag + validation) → `report.Options` or
`scan.Options` (plumbing) → README flags table → a `cmd` test.

---

## 13. Roadmap and why

| Priority | Work | Why it is the next thing |
|----------|------|--------------------------|
| done | ~~POST and form parameters~~ | Shipped in 0.5.0 as `-forms`: forms parsed, GET forms folded into the URL path, POST probing opt-in with same-origin and destructive filters. |
| done | ~~SARIF output~~ | Shipped in 0.6.0 as `-sarif`. |
| done | ~~More secret rules~~ | Shipped in 0.7.0: JSON-escaped PEM, Discord webhooks, Telegram bot tokens, Azure SAS. |
| 1 | **Stored / blind reflection** | Requires a second fetch later in the run; a different detection model from the current single-shot probe. |
| 2 | **Multi-page crawl** | The tool scans exactly one page. Following same-site links (depth 1, capped) would multiply coverage but also request count — gate it behind a flag. |
| 3 | **Live credential validation** | Only behind an explicit flag and only against providers with a harmless "who am I" endpoint. It converts structural scores into confirmed ones, but it is the only feature that would make the tool talk to third parties. Treat as a design decision, not a chore. |

Explicitly **not** planned: evasion, WAF bypass, exploit payloads. The tool
reports evidence; it does not weaponise it.

---

## 14. Known limitations (be honest about these)

- Single page, `GET` only. No forms, no JSON bodies, no cookies beyond `-cookie`.
- No stored/blind XSS, no DOM XSS analysis (the `js` module extracts endpoints,
  it does not execute or symbolically evaluate JavaScript).
- Path scanning uses a fixed 26-entry list.
- Third-party detection uses a small suffix table, so exotic TLDs (`co.zw`,
  `com.ar`) may be misclassified.
- JWTs are reported on structure alone; many are legitimately public.
- Low-entropy real tokens are rejected by design.
- No retry/backoff: a transient 503 is simply skipped.

---

## 15. Git history

| Commit | Subject | What changed |
|--------|---------|--------------|
| `86b9b12` | feat: bootstrap SoliTools with explainable confidence scoring and precision-first secret detection | first version: a **file** scanner with 15 rules and the scoring model |
| `fc86342` | feat: rebuild SoliTools as a URL-based web scanner with six modules | replaced the file walker with the HTTP pipeline; added js, param, reflect, redirect, pathscan; bands rebased to 60/75/90 |
| `2e20a0d` | feat(ui): color the terminal report and add a live scan status | `term`, `progress`, badges, boxed summary, `-color`, VT mode |
| `d5dd2ac` | feat(ui): wrap long values to terminal width and add `-quiet` | width detection for Windows/Linux/BSD, hanging-indent wrapping, CI summary |

The rewrite in `fc86342` deleted the file-scanning API on purpose. If you find
leftover references to `ScanPaths`, `Options.IncludeGeneric`, or a `pathPenalty`
signal, they are stale — the current API is `Scanner.Scan(Document)` with no
threshold inside the scanner.

---

## 16. Open questions worth raising before you build them

1. **`-mask` defaults to on.** The product brief listed it as an opt-in flag but
   also showed masked output. The current default protects logs; confirm the
   user still prefers that.
2. **POST design.** Decided in 0.5.0: `-forms` is opt-in, actions must be
   same-origin, file inputs and destructive-looking forms are skipped, and every
   other field keeps its default value so CSRF tokens survive. If this is ever
   enabled by default, re-open the decision — a form submission can create
   records or send mail.
3. **Live validation.** Any provider check means contacting a third party with a
   user's credential. That is a product decision, not an implementation detail.
4. **Crawl depth.** Multi-page scanning multiplies requests; decide whether it
   is a flag, a default cap, or out of scope.
5. **Wordlist ownership.** Fixed list today. A `-wordlist` file would be useful
   but invites 100k-line noise, which contradicts the precision thesis.
6. **Generic rules.** They live in the default set and rely on score arithmetic
   to stay quiet. A `-generic` switch would be more explicit — but one more flag.
7. **Versioning.** `0.4.0` exists only in code; there are no tags and no remote.
   Tag releases if this is going to be distributed.
8. **No CI.** Verification is local. A workflow would need the same three
   commands plus the GOCACHE reminder.

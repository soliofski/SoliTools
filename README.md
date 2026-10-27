# SoliTools

High-accuracy web security analysis in Go. The design rule for this project is
simple: **a finding must be worth a human's time**. Precision is preferred over
recall at every decision point, and anything that is filtered out is counted
and explained rather than silently dropped.

Current state: the confidence model and the secret module are implemented and
tested. The `js` and `reflect` modules are not written yet — see
[Roadmap](#roadmap).

## Usage

```
solitools scan [flags] <path>...

  -min-confidence float   drop findings below this score (0 uses default 40)
  -generic                add the low-precision generic rules
  -json                   emit a JSON report
```

```console
$ solitools scan .
internal/app/config.go:14:18  secret.github-token  confidence 70.0 (high)
    GitHub token
    match ghp_********************************3N  fp 5ce1bae32a8f7923
    score 90.0 -> 70.0  path-context -20.0 (path looks like a test fixture)

Scanned 19 files (66.4 KiB) in 29ms
Findings: 1 (1 high or very-high)
Suppressed: 2 (placeholder 2)
```

Exit codes: `0` no findings, `1` findings reported, `2` usage or runtime error.

The binary writes nothing but the report: no network calls, no file
modification, no telemetry.

## Confidence model

Every finding starts at the base confidence its rule declares and is adjusted by
named signals. The full trace is attached to the finding, so any score can be
reconstructed and argued with after the fact. There is no opaque model and no
randomness; the same bytes always produce the same score.

| Band        | Range      | Meaning                                        |
| ----------- | ---------- | ---------------------------------------------- |
| `low`       | `[0, 40)`  | usually noise, hidden by default               |
| `medium`    | `[40, 70)` | worth a human look                             |
| `high`      | `[70, 90)` | likely a real finding                          |
| `very-high` | `[90, 100]`| provider-identified and structurally valid     |

Two mechanisms are deliberately kept apart:

- **Gates** reject a candidate outright — a malformed value is not a weak
  finding, it is not a finding. Gates never produce a score.
- **Signals** adjust confidence and are always visible in `confidence.signals`.

Current signals: `generic-rule` (−10), `path-context` (−20 for test fixtures,
−10 for docs and samples), plus any advisory validator a rule attaches.

`-min-confidence` defaults to 40, the bottom of the medium band. Lowering it to
`1` reports everything; suppressed findings are always counted per reason in the
summary so the filter can be audited.

## Secret module

### What makes it precise

1. **Provider identity is required.** Every default rule has a reserved prefix
   (`ghp_`, `sk_live_`, `AIza`, …) or an unambiguous structure (a PEM block that
   base64-decodes to real DER). Nothing in the default set is "keyword plus
   entropy", which is the dominant source of false positives in secret scanning.
2. **Gates, not penalties, for malformed values.** Length bounds, entropy
   floors, placeholder detection and structural requirements reject a candidate
   before it can be scored.
3. **Entropy is measured on the payload, not the prefix.** `sk_live_` is
   stripped before the entropy check, so a low-entropy literal cannot make a
   real token look random, and a low-entropy prefix cannot mask an empty one.
4. **The canonical documentation keys are rejected by name.** `…EXAMPLE`
   payloads never reach the report.
5. **Padding is rejected structurally.** A payload with three or fewer distinct
   characters, or a run of eight identical characters, is not a credential.
6. **Context lowers rank instead of hiding evidence.** A match under
   `testdata/`, `fixtures/` or `*_test.go` drops 20 points but is still
   reported: fixtures can contain real keys copied in by mistake.

### Reporting safety

`match` is always redacted: the first four characters identify the provider, the
last two distinguish similar findings, and the middle is masked (capped at 32
stars). PEM blocks keep their header only. `fingerprint` is the first 16 hex
characters of SHA-256 over the whitespace-stripped payload, so the same secret
can be correlated across files without ever being printed. Reports are safe to
paste into tickets and CI logs.

### Rules

| Rule | Base | Structure |
| --- | --- | --- |
| `secret.private-key` | 95 | PEM block; body must base64-decode to ≥64 bytes of DER |
| `secret.aws-access-key-id` | 85 | `AKIA`/`ASIA`/… + 16 chars, entropy ≥ 3.0 |
| `secret.github-token` | 90 | `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 36, entropy ≥ 3.5 |
| `secret.github-fine-grained-pat` | 90 | `github_pat_` + 22 + `_` + 59, entropy ≥ 3.5 |
| `secret.slack-token` | 85 | `xoxb-`/`xoxp-`/… , entropy ≥ 2.0 (digits-heavy tokens) |
| `secret.google-api-key` | 80 | `AIza` + 35, entropy ≥ 3.0 |
| `secret.stripe-live-key` | 90 | `sk_live_`/`rk_live_` + 24…247, entropy ≥ 3.0 |
| `secret.stripe-test-key` | 30 | `sk_test_`/`rk_test_`; below the default threshold by design |
| `secret.anthropic-api-key` | 90 | `sk-ant-api03-`…, entropy ≥ 3.5 |
| `secret.openai-api-key` | 85 | `sk-proj-`/`sk-svcacct-`/`sk-admin-`…, entropy ≥ 3.5 |
| `secret.gitlab-pat` | 85 | `glpat-` + 20, entropy ≥ 3.0 |
| `secret.npm-token` | 85 | `npm_` + 36, entropy ≥ 3.5 |
| `secret.sendgrid-api-key` | 85 | `SG.` + 22 + `.` + 43, entropy ≥ 3.5 |
| `secret.twilio-api-key` | 70 | `SK` + 32 hex, entropy ≥ 2.5 |
| `secret.azure-storage-key` | 85 | `AccountKey=` + 86…90 base64, entropy ≥ 4.0 |

Opt-in via `-generic`:

| Rule | Base | Structure |
| --- | --- | --- |
| `secret.generic-assignment` | 55 | `password`/`api_key`/… `=` `"value"`, entropy ≥ 3.2 |
| `secret.generic-high-entropy` | 45 | bare 40…64 char random string, entropy ≥ 4.2 |

Entropy is Shannon entropy in bits per symbol.

Stripe test keys sit at base 30 on purpose: they cannot move money, and treating
them as incidents trains people to ignore the report. They are still visible at
`-min-confidence 30`.

## Known limitations

These are accepted trade-offs, not oversights:

- **Unusual low-entropy tokens are rejected.** A real credential with few
  distinct symbols will not be reported. Precision beats recall here.
- **No live validation.** The tool never contacts a provider to confirm a key.
  That keeps runs offline and deterministic.
- **No JWT, basic-auth URL or JSON-escaped PEM rule yet.** Private keys embedded
  as `\n`-escaped strings are missed; that is the next secret-module gap.
- **Working tree only.** Git history and commit messages are not scanned.
- **Binary detection is a NUL scan of the first 8 KiB** plus an extension list.
- **Symlinked files are skipped** during a directory walk.
- **Default ignore list.** `.git`, `node_modules`, `vendor`, `.venv` and similar
  directories are skipped unless `IgnoreDirs` is set explicitly.

## Roadmap

Ordered by the project's priority list:

1. ~~Confidence Score system~~ — done.
2. ~~Secret module~~ — done; next gap is JSON-escaped PEM and JWT structure.
3. **`js` module** — extract endpoints and embedded credentials from bundles,
   with source-map awareness and per-bundle deduplication.
4. **`reflect` module** — analyze request/response pairs for input reflection,
   with context classification to keep output encoding advice accurate.
5. **Correlation** — fingerprint-based grouping across files and runs.

## Development

```
go test ./...
go vet ./...
gofmt -l .
```

Rules and their gates live in `internal/secret/rules.go`; the scoring model is
`internal/confidence`. Adding a rule requires a positive test and at least one
false-positive regression in `internal/secret/scanner_test.go` — the false
positives are the specification, not an afterthought.

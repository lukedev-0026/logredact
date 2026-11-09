# Roadmap

This is the plan after 0.1.0. Estimates are for one developer and include
tests and documentation. Priorities: **P1** next, **P2** soon, **P3** later.
Each item is tracked as a GitHub issue.

Total estimated remaining work: **about 50 hours**.

## Milestone 0.2: coverage (≈16 h)

| Item | Priority | Estimate | Acceptance criteria |
| --- | --- | --- | --- |
| Phone number detector | P1 | 5 h | E.164 and common national formats are pseudonymised. False positives on timestamps, IDs and port numbers are measured on a synthetic corpus and stay under 1%. |
| More credential formats | P1 | 4 h | npm, PyPI, Docker Hub, Azure storage, Twilio, SendGrid and OpenAI-style keys, each with positive and near-miss tests and, where the format has one, checksum validation. |
| Structured JSON logs | P2 | 5 h | `--json-lines` redacts by field name (for example `user.email`) as well as by pattern, keeps valid JSON, and supports `fields = [...]` in configuration. |
| IPv4 version-string guard | P3 | 2 h | Values preceded by `v`, `version` or `ver` are not treated as IPv4; tests cover common version formats. |

## Milestone 0.3: performance (≈12 h)

| Item | Priority | Estimate | Acceptance criteria |
| --- | --- | --- | --- |
| Literal prefilter | P1 | 5 h | Each detector declares cheap trigger substrings (`@`, `eyJ`, `://`, …); lines without any skip that detector. Throughput on the benchmark corpus at least triples. |
| Benchmark in CI | P1 | 2 h | A 100,000-line synthetic corpus runs in CI and the job fails if throughput drops by more than 25%. |
| Parallel files | P2 | 3 h | `--jobs N` redacts multiple input files in parallel, keeping output order. |
| Single-pass masking | P3 | 2 h | Replace string rebuilding with an offset list so lines with many matches stay linear. |

## Milestone 0.4: workflow (≈12 h)

| Item | Priority | Estimate | Acceptance criteria |
| --- | --- | --- | --- |
| In-place redaction with backup | P2 | 3 h | `--in-place` writes atomically via a temporary file and keeps `FILE.orig` unless `--no-backup` is given. |
| Pseudonym mapping export | P2 | 4 h | `--mapping FILE` writes original-to-pseudonym pairs (encrypted with a passphrase) so the owner can reverse a shared log locally. |
| GitHub Action | P2 | 3 h | An `action.yml` runs `--check` on chosen paths and fails the job, with an annotations output for pull requests. |
| Archive support | P3 | 2 h | `.gz` input is read transparently and `-o *.gz` writes compressed output. |

## Milestone 1.0: distribution and hardening (≈10 h)

| Item | Priority | Estimate | Acceptance criteria |
| --- | --- | --- | --- |
| Publish to PyPI with trusted publishing | P1 | 2 h | Tagged releases upload to PyPI without stored tokens; README install instructions updated. |
| Pin GitHub Actions to commit SHAs | P1 | 1 h | All `uses:` lines reference full SHAs with version comments; Dependabot keeps them current. |
| Detection-quality corpus | P1 | 4 h | A labelled synthetic corpus reports precision and recall per detector in CI, and regressions fail the build. |
| ReDoS review | P2 | 2 h | Every built-in pattern is checked against catastrophic backtracking with a fuzzing harness, and worst-case time per 10 KB line stays under 50 ms. |
| Documentation site | P3 | 1 h | `docs/` is published with GitHub Pages on each release. |

## Not planned

- Machine-learning entity recognition for names and addresses. It would add
  heavy dependencies; integrating an external recogniser as a plugin may be
  considered after 1.0.
- Network services or uploading logs anywhere. logredact only reads and
  writes local files and streams.

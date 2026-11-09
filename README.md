# logredact

[![CI](https://github.com/lukedev-0026/logredact/actions/workflows/ci.yml/badge.svg)](https://github.com/lukedev-0026/logredact/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

logredact strips secrets and personal data from logs before you share them,
and keeps the logs useful for debugging.

```console
$ echo 'GET /api?token=Zt9qL2xw from 198.51.100.23 by ana@example.com' | logredact
GET /api?token=[REDACTED:assigned-secret] from 241.4.201.49 by user-3a95a67e02@redacted.invalid
```

Secrets are removed outright. Personal data such as emails and IP addresses is
replaced with a **consistent pseudonym**: the same address always becomes the
same fake address, so you can still see that one user failed to log in three
times, or that every error came from one client, without revealing who.

## Who it is for

- **Developers and support engineers** pasting logs into bug reports, chat or
  support tickets.
- **Open-source maintainers** who ask users to attach logs.
- **Teams with privacy obligations** who must keep personal data out of
  ticketing systems and third-party tools.

## Features

- 18 built-in detectors (see [docs/detectors.md](docs/detectors.md)):
  - private keys;
  - AWS, GitHub, GitLab, Slack, Stripe and Google credentials;
  - JWTs and `Authorization` headers;
  - passwords in URLs and in `password=`/`api_key:`-style assignments;
  - card numbers, emails, and IPv4 and IPv6 addresses.
- Validators cut false positives: GitHub token checksums, Luhn and card
  prefixes, JWT headers, and real address parsing. Placeholders like `***`
  and `${PASSWORD}` are left alone, as are loopback addresses.
- Pseudonyms keep their shape. Emails become `user-…@redacted.invalid`,
  IPv4 addresses land in the reserved `240.0.0.0/4` range, and IPv6 in
  `2001:db8::/32`, so log parsers keep working. They are HMAC-SHA256 keyed,
  so they cannot be reversed by guessing.
- **Idempotent:** redacting already-redacted output changes nothing, and
  `--check` on it reports nothing. Property-based tests check this.
- `--check` mode reports what would be redacted, as text or JSON, never the
  values themselves. Usable in CI and as a pre-commit hook.
- Custom regex rules, allowlists and disabled detectors via `logredact.toml`
  or `[tool.logredact]` in `pyproject.toml`.
- Streams input line by line, keeps line endings and undecodable bytes intact,
  and catches multi-line private keys.
- No runtime dependencies, and a small Python API.

## Stack

Python 3.11+ standard library only. Development uses
[uv](https://docs.astral.sh/uv/), pytest, [Hypothesis](https://hypothesis.works/),
ruff and mypy (strict).

## Installation

logredact is not on PyPI yet. Install it from GitHub:

```sh
pipx install git+https://github.com/lukedev-0026/logredact
# or
uv tool install git+https://github.com/lukedev-0026/logredact
```

## Usage

```sh
logredact app.log > safe.log            # or: logredact app.log -o safe.log
kubectl logs pod/api | logredact        # standard input
logredact a.log b.log --stats           # counts per detector on stderr
logredact --check app.log               # list findings, exit 1 if any
logredact --check --format json app.log
logredact --list-detectors
```

`--check` output never includes the sensitive value:

```console
$ printf 'Authorization: Bearer abcdefgh123\n' | logredact --check
<stdin>:1:23: authorization-header (secret)
1 sensitive value(s) found.
```

The [examples](examples) folder has a synthetic [sample.log](examples/sample.log)
and its [redacted output](examples/sample.redacted.log).

### Stable pseudonyms

Without a key, logredact generates a random one per run. Pseudonyms are then
consistent within one output but cannot be linked across runs. To get the same
pseudonyms every time, for example to compare logs from two days, provide a
key of at least 16 bytes:

```sh
export LOGREDACT_KEY="$(openssl rand -hex 32)"   # keep this private
logredact monday.log > monday.safe.log
logredact tuesday.log > tuesday.safe.log
```

`--key-env NAME` reads the key from a different variable. Anyone with the key
can check guesses ("is user-3a95… ana@example.com?"), so treat it like a
password and never share it alongside the redacted logs.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success; with `--check`, nothing found |
| 1 | `--check` found something |
| 2 | Usage, configuration, file or key error |

## Configuration

logredact uses the nearest `logredact.toml`, or `[tool.logredact]` in
`pyproject.toml`, searching upward from the working directory. You can also pass
`--config FILE`.

```toml
disable = ["ipv4"]                    # built-in or custom detector names
allow = ["support@example.com"]       # exact values never redacted
allow-patterns = ['10\..*']           # regexes matched against the whole value
key-env = "LOGREDACT_KEY"             # variable holding the pseudonym key

[[rules]]                             # custom detectors run before built-ins
name = "order-id"
pattern = 'ORD-\d{5}'
action = "pseudonymize"               # or "redact" (default)
category = "pii"                      # or "secret" (default)
group = 0                             # capture group holding the value
```

## Python API

```python
from logredact import Redactor

redactor = Redactor(key=b"a-key-of-at-least-16-bytes")
result = redactor.redact("login from 203.0.113.9 by ana@example.com")
print(result.text)
for finding in result.findings:          # detector, category, line, column, length
    print(finding.detector, finding.line, finding.column)
```

## pre-commit

Block commits of log files that contain secrets or personal data:

```yaml
repos:
  - repo: https://github.com/lukedev-0026/logredact
    rev: v0.1.0
    hooks:
      - id: logredact
```

## Limitations

logredact uses patterns, not understanding. Know what it does not do before
you rely on it:

- **It does not find** names, postal addresses, phone numbers, national ID
  numbers, or secrets with no recognisable shape or label. Add custom rules
  for formats you know, and review output before sharing anything highly
  sensitive.
- **False positives:** a version string such as `1.2.3.4` is treated as an
  IPv4 address. Any value assigned to a name ending in `token`, `secret` or
  `password` is redacted.
- Addresses already in the ranges used for pseudonyms (`240.0.0.0/4`,
  `2001:db8::/32`) and emails at `redacted.invalid` are left alone, so that
  redaction is idempotent.
- **Speed:** about 1 MB/s on one core: 100,000 typical log lines (10 MB) take
  around 10 seconds. That is fine for sharing logs but not for a log pipeline.
  Faster matching is on the [roadmap](ROADMAP.md).

## Development and testing

```sh
git clone https://github.com/lukedev-0026/logredact
cd logredact
uv sync
uv run pytest                 # unit, property-based, CLI and end-to-end tests
uv run ruff check . && uv run ruff format --check .
uv run mypy
```

Test credentials are assembled at runtime in [tests/fakes.py](tests/fakes.py),
so no complete token-shaped string is stored in the repository.

## Contributing

New detectors, fewer false positives and bug reports are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [ROADMAP.md](ROADMAP.md). Report
security issues as described in [SECURITY.md](SECURITY.md).

## Project history

logredact was started on 9 November 2026. See
[PROJECT_HISTORY.md](PROJECT_HISTORY.md) and [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE) © 2026 Luke Taaffe

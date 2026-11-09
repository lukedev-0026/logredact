# Detectors

Detectors run in the order below. When matches overlap, the earlier detector
wins, and custom rules from the configuration run before all of them.
**Secrets** are replaced with `[REDACTED:<name>]`. **Personal data** is
pseudonymised (emails and IP addresses) or redacted (card numbers).

Disable a detector with `--disable NAME` or `disable = ["NAME"]`.

| Name | Category | Action | Matches |
| --- | --- | --- | --- |
| `private-key` | secret | redact | PEM blocks from `-----BEGIN … PRIVATE KEY-----` to the matching END line, including across lines |
| `aws-access-key-id` | secret | redact | `AKIA`, `ASIA`, `ABIA` or `ACCA` followed by 16 base-32 characters |
| `aws-secret-access-key` | secret | redact | A 40-character key directly after `aws_secret_access_key` (any case, `=` or `:`) |
| `github-token` | secret | redact | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` tokens whose built-in CRC32 checksum is valid |
| `github-fine-grained-token` | secret | redact | `github_pat_` tokens |
| `gitlab-token` | secret | redact | `glpat-` tokens |
| `slack-token` | secret | redact | `xoxb-`, `xoxp-` and similar tokens |
| `slack-webhook` | secret | redact | `https://hooks.slack.com/services/…` URLs |
| `stripe-key` | secret | redact | `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_` keys |
| `google-api-key` | secret | redact | `AIza` followed by 35 characters |
| `jwt` | secret | redact | Three-part `eyJ….eyJ….…` tokens whose header decodes to JSON with `alg` or `typ` |
| `authorization-header` | secret | redact | The credential after `Authorization:` or `Proxy-Authorization:` with Bearer, Basic, Token or Digest |
| `url-credentials` | secret | redact | The password in `scheme://user:password@host` |
| `assigned-secret` | secret | redact | The value after a name containing `password`, `passwd`, `pwd`, `secret`, `api_key`, `access_token`, `auth_token`, `refresh_token` or `token`, followed by `=` or `:` |
| `card-number` | pii | redact | 13–19 digits, optionally grouped by spaces or dashes, with a known card prefix and a valid Luhn checksum |
| `email` | pii | pseudonymize | Email addresses, becoming `user-<10 hex>@redacted.invalid` |
| `ipv6` | pii | pseudonymize | IPv6 addresses, including ones with an IPv4 tail, becoming an address in `2001:db8::/32` |
| `ipv4` | pii | pseudonymize | IPv4 addresses, becoming an address in `240.0.0.0/4` |

## What is left alone

- Loopback and unspecified addresses (`127.0.0.1`, `0.0.0.0`, `::1`, `::`) and
  `255.255.255.255`.
- `assigned-secret` values that are placeholders: `***`, `xxxx`, `${VAR}`,
  `$(cmd)`, `{{ template }}`, `<redacted>`, `null`, `none`, `true`, `false`,
  `changeme`, or values shorter than four characters.
- Values already produced by logredact: `[REDACTED:…]` markers, emails at
  `redacted.invalid`, and addresses in the pseudonym ranges.
- Values listed in `allow` or fully matching `allow-patterns`.

## How overlapping and adjacent values are handled

Each detector sees the text with earlier matches masked out. Masking can
expose a value that was glued to the masked one, for example a URL straight
after a card number. So whenever a detector masks something, matching starts
again from the first detector, and it ends when a full pass finds nothing new.
This keeps priority consistent and makes redaction idempotent. Property-based
tests check both.

## Pseudonyms

A pseudonym is the HMAC-SHA256 of the detector kind and the value, under the
key from `LOGREDACT_KEY` (or `--key-env`), or a random per-run key if none is
set. Emails are lower-cased first, so `Ana@Example.com` and `ana@example.com`
map to the same pseudonym.

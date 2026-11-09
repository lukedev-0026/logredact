# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-09

First release.

### Added

- 18 detectors for private keys, cloud and SaaS credentials, JWTs,
  Authorization headers, URL and assigned passwords, card numbers, emails,
  and IPv4/IPv6 addresses, with validators that reject look-alikes.
- Keyed HMAC-SHA256 pseudonyms for emails and IP addresses that keep their
  shape, using reserved ranges so output is never detected again.
- Idempotent redaction, checked by property-based tests.
- Streaming redaction that keeps line endings and undecodable bytes and
  catches multi-line private keys.
- `logredact` command with `-o`, `--check` (text or JSON, never printing
  values), `--stats`, `--disable`, `--allow`, `--key-env` and
  `--list-detectors`.
- Configuration in `logredact.toml` or `[tool.logredact]`, with custom
  rules, allowlists and allow-patterns.
- Python API (`Redactor`, `Finding`, `Detector`).
- pre-commit hook.

[Unreleased]: https://github.com/lukedev-0026/logredact/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lukedev-0026/logredact/releases/tag/v0.1.0

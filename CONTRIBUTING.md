# Contributing to logredact

Thanks for your interest. New detectors, fewer false positives, bug reports
and documentation fixes are all welcome.

## Ground rules

- **Never commit real secrets or personal data**, not even expired or
  revoked ones. Use made-up values. Build token-shaped test values at runtime
  in `tests/fakes.py`, so the repository never contains a complete token
  string that secret scanners would flag.
- For anything larger than a small fix, open an issue first.
- Check [ROADMAP.md](ROADMAP.md) and the open issues before starting.
- By contributing you agree that your work is released under the
  [MIT License](LICENSE), and you confirm you have the right to submit it.
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Setting up

You need Python 3.11 or newer and [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/lukedev-0026/logredact
cd logredact
uv sync
```

## Checks to run before a pull request

```sh
uv run ruff format .
uv run ruff check .
uv run mypy
uv run pytest
```

CI runs the same checks on Linux, Windows and macOS with Python 3.11–3.13.

## Code layout

| Path | Contents |
| --- | --- |
| `src/logredact/detectors.py` | Built-in detectors and their validators |
| `src/logredact/pseudonym.py` | Keyed pseudonyms |
| `src/logredact/redactor.py` | Matching, masking, replacement and streaming |
| `src/logredact/config.py` | Configuration files and custom rules |
| `src/logredact/cli.py` | Command-line interface |
| `tests/fakes.py` | Synthetic credentials built at runtime |
| `examples/` | Synthetic sample log, config and redacted snapshot |

## Adding a detector

1. Add it to `BUILTIN_DETECTORS` in `detectors.py`. Its position sets its
   priority: specific formats go before general ones.
2. Exclude NUL (`\x00`) from any negated character class (`[^...]`). The
   engine uses NUL to mask earlier matches.
3. Add a validator if the format has a checksum or structure that can reject
   look-alikes.
4. Add tests in `tests/test_detectors.py`: whole-token matches, and near
   misses that must not match.
5. If the detector could interact with neighbours, add a sample to the
   Hypothesis strategy in `tests/test_redactor.py`. Run it once with a higher
   `max_examples` locally.
6. Document it in `docs/detectors.md`, and regenerate
   `examples/sample.redacted.log` if the sample is affected:
   `LOGREDACT_KEY=demo-key-not-secret-0001 uv run logredact --config examples/logredact.toml examples/sample.log -o examples/sample.redacted.log`.

## Commit messages

Use an imperative summary of 72 characters or fewer, a blank line, then what
changed and why. Keep each commit focused on one change.

## Releasing (maintainers)

1. Update `__version__` in `src/logredact/__init__.py` and move the
   `Unreleased` entries in `CHANGELOG.md` under the new version.
2. Commit, tag `vX.Y.Z` and push the tag. The release workflow checks the tag
   matches the version, runs the tests, builds the package and creates the
   GitHub release.

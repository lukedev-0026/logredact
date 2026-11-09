# Project history

## Start

logredact was started by Luke Taaffe on **9 November 2026** as an independent
personal project. The commit history in this repository is the complete
development record, and every commit carries the date it was actually made.

## Timeline

| Date | Milestone |
| --- | --- |
| 2026-11-09 | Project skeleton, packaging and MIT license |
| 2026-11-09 | Detectors for secrets and personal data, with validators |
| 2026-11-09 | Redaction engine with keyed pseudonyms and streaming |
| 2026-11-09 | Command line, configuration files and custom rules |
| 2026-11-09 | Synthetic sample log and end-to-end snapshot test |
| 2026-11-09 | Fixes for adjacent-value leaks found by property-based tests |
| 2026-11-09 | CI on three operating systems, release workflow, pre-commit hook |
| 2026-11-09 | Documentation and version 0.1.0 |

## Notable decisions

- **Property-based testing found real leaks before release.** Hypothesis
  showed that a value glued to another (an email straight after a card
  number, a URL password after digits) could be missed on the first pass. The
  fix was to mask matches and restart detection, not to patch each pattern.
  See the commits on 9 November 2026 for details.
- **No runtime dependencies**, so the tool is easy to vet before running it
  on sensitive data.

Planned work is in [ROADMAP.md](ROADMAP.md), and released changes are in
[CHANGELOG.md](CHANGELOG.md).

## How it was built

The code was written with the help of an AI coding assistant (Claude Code),
under the direction and review of the maintainer.

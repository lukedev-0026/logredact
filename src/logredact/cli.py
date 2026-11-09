"""Command-line interface."""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
from collections import Counter
from collections.abc import Iterator, Sequence
from contextlib import ExitStack
from pathlib import Path
from typing import IO

from logredact import __version__
from logredact.config import Config, ConfigError, build_detectors, find_config, load_config
from logredact.detectors import Detector
from logredact.redactor import Finding, Redactor

__all__ = ["main", "run"]

EXIT_OK, EXIT_FOUND, EXIT_ERROR = 0, 1, 2


class _UsageError(Exception):
    pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logredact",
        description=(
            "Remove secrets and personal data from logs. Reads FILEs (or standard input) "
            "and writes the redacted text to standard output."
        ),
        epilog="Exit status: 0 success, 1 --check found something, 2 error.",
    )
    parser.add_argument("files", nargs="*", metavar="FILE", help="input files; '-' is stdin")
    parser.add_argument("-o", "--output", metavar="FILE", help="write here instead of stdout")
    parser.add_argument(
        "--check",
        action="store_true",
        help="report what would be redacted (without the values) and exit 1 if anything is found",
    )
    parser.add_argument(
        "--format", choices=["text", "json"], default="text", help="report format for --check"
    )
    parser.add_argument("--config", metavar="FILE", help="settings file (default: nearest "
                        "logredact.toml or pyproject.toml)")  # fmt: skip
    parser.add_argument(
        "--disable", action="append", default=[], metavar="DETECTOR", help="repeatable"
    )
    parser.add_argument(
        "--allow", action="append", default=[], metavar="VALUE", help="never redact VALUE"
    )
    parser.add_argument(
        "--key-env",
        metavar="VAR",
        help="environment variable holding the pseudonym key (default: LOGREDACT_KEY); "
        "without a key, pseudonyms differ on every run",
    )
    parser.add_argument("--stats", action="store_true", help="print counts to stderr")
    parser.add_argument("--list-detectors", action="store_true", help="list detectors and exit")
    parser.add_argument("--version", action="version", version=f"logredact {__version__}")
    return parser


def run(
    argv: Sequence[str] | None = None,
    *,
    stdin: IO[bytes] | None = None,
    stdout: IO[bytes] | None = None,
    stderr: IO[str] | None = None,
) -> int:
    stdin = stdin if stdin is not None else sys.stdin.buffer
    stdout = stdout if stdout is not None else sys.stdout.buffer
    stderr = stderr if stderr is not None else sys.stderr
    args = _parser().parse_args(argv)
    try:
        config = _load(args.config)
        detectors = build_detectors(config, tuple(args.disable))
        if args.list_detectors:
            _write(stdout, _detector_table(detectors))
            return EXIT_OK
        redactor = Redactor(
            detectors,
            key=_key(args.key_env or config.key_env, explicit=args.key_env is not None),
            allow=(*config.allow, *args.allow),
            allow_patterns=config.allow_patterns,
        )
        inputs = args.files or ["-"]
        if args.output and any(_same_file(args.output, f) for f in inputs if f != "-"):
            raise _UsageError("output file is also an input file")
        if args.check:
            return _check(redactor, inputs, stdin, stdout, args.format)
        counts = _redact(redactor, inputs, stdin, stdout, args.output)
    except (ConfigError, _UsageError, ValueError, OSError) as exc:
        print(f"logredact: error: {exc}", file=stderr)
        return EXIT_ERROR
    if args.stats:
        total = sum(counts.values())
        detail = ", ".join(f"{name} {n}" for name, n in counts.most_common())
        print(f"logredact: redacted {total} value(s)" + (f": {detail}" if detail else ""),
              file=stderr)  # fmt: skip
    return EXIT_OK


def main() -> None:
    sys.exit(run())


def _load(path: str | None) -> Config:
    if path is not None:
        return load_config(Path(path))
    found = find_config(Path.cwd())
    return load_config(found) if found else Config()


def _key(env_name: str, *, explicit: bool) -> bytes | None:
    value = os.environ.get(env_name)
    if value is None:
        if explicit:
            raise _UsageError(f"environment variable {env_name} is not set")
        return None
    return value.encode("utf-8")


def _same_file(a: str, b: str) -> bool:
    try:
        return Path(a).resolve() == Path(b).resolve()
    except OSError:
        return False


def _lines(name: str, stdin: IO[bytes]) -> Iterator[tuple[str, str]]:
    """Yield (display name, line) for each line of each input, keeping line endings."""
    if name == "-":
        stream = io.TextIOWrapper(stdin, encoding="utf-8", errors="surrogateescape", newline="")
        try:
            for line in stream:
                yield "<stdin>", line
        finally:
            stream.detach()
        return
    with Path(name).open(encoding="utf-8", errors="surrogateescape", newline="") as handle:
        for line in handle:
            yield name, line


def _redact(
    redactor: Redactor, inputs: list[str], stdin: IO[bytes], stdout: IO[bytes], output: str | None
) -> Counter[str]:
    counts: Counter[str] = Counter()
    for name in inputs:
        if name != "-" and not Path(name).is_file():
            raise _UsageError(f"{name}: no such file")
    with ExitStack() as stack:
        target: IO[bytes] = stack.enter_context(Path(output).open("wb")) if output else stdout
        for name in inputs:
            for result in redactor.redact_lines(line for _, line in _lines(name, stdin)):
                target.write(result.text.encode("utf-8", "surrogateescape"))
                counts.update(f.detector for f in result.findings)
        target.flush()
    return counts


def _check(
    redactor: Redactor, inputs: list[str], stdin: IO[bytes], stdout: IO[bytes], fmt: str
) -> int:
    report: list[tuple[str, Finding]] = []
    for name in inputs:
        if name != "-" and not Path(name).is_file():
            raise _UsageError(f"{name}: no such file")
        shown = "<stdin>" if name == "-" else name
        for result in redactor.redact_lines(line for _, line in _lines(name, stdin)):
            report.extend((shown, f) for f in result.findings)

    if fmt == "json":
        payload = {
            "total": len(report),
            "findings": [
                {
                    "path": path,
                    "line": f.line,
                    "column": f.column,
                    "length": f.length,
                    "detector": f.detector,
                    "category": f.category.value,
                }
                for path, f in report
            ],
        }
        _write(stdout, json.dumps(payload, indent=2) + "\n")
    else:
        lines = [
            f"{path}:{f.line}:{f.column}: {f.detector} ({f.category.value})" for path, f in report
        ]
        lines.append(f"{len(report)} sensitive value(s) found." if report else "Nothing found.")
        _write(stdout, "\n".join(lines) + "\n")
    return EXIT_FOUND if report else EXIT_OK


def _detector_table(detectors: Sequence[Detector]) -> str:
    rows = [
        f"{d.name:<27} {d.category.value:<7} {d.action.value:<13} {d.description}"
        for d in detectors
    ]
    return "\n".join(rows) + "\n"


def _write(stream: IO[bytes], text: str) -> None:
    stream.write(text.encode("utf-8"))
    stream.flush()

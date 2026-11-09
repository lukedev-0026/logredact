"""Finding and replacing sensitive values in text."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass

from logredact.detectors import BUILTIN_DETECTORS, Action, Category, Detector, Match
from logredact.pseudonym import Pseudonymizer

__all__ = ["Finding", "RedactionResult", "Redactor"]

#: A multi-line private key is buffered for at most this many lines.
MAX_BLOCK_LINES = 500

_BLOCK_START = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_BLOCK_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY-----")
#: Fills already-matched spans. No detector matches across a line break
#: except the private-key detector, which runs first.
_MASK = "\n"


@dataclass(frozen=True)
class Finding:
    """Where a sensitive value was found. The value itself is never kept."""

    detector: str
    category: Category
    line: int
    column: int
    length: int


@dataclass(frozen=True)
class RedactionResult:
    text: str
    findings: list[Finding]


class Redactor:
    """Detects sensitive values and replaces them.

    Detectors earlier in ``detectors`` take priority when matches overlap.
    Values in ``allow``, or fully matching a pattern in ``allow_patterns``,
    are left unchanged.
    """

    def __init__(
        self,
        detectors: Sequence[Detector] = BUILTIN_DETECTORS,
        *,
        key: bytes | None = None,
        allow: Iterable[str] = (),
        allow_patterns: Iterable[str | re.Pattern[str]] = (),
    ) -> None:
        self.detectors = tuple(detectors)
        self.pseudonymizer = Pseudonymizer(key)
        self.allow = frozenset(allow)
        self.allow_patterns = tuple(
            p if isinstance(p, re.Pattern) else re.compile(p) for p in allow_patterns
        )

    # -- matching ---------------------------------------------------------

    def matches(self, text: str) -> list[Match]:
        """Return non-overlapping matches in ``text``, ordered by position.

        Detectors run in priority order. Each one sees the text with earlier
        matches masked out (replaced by line breaks of the same length), so
        a value cannot hide a neighbour it touches and offsets stay valid.
        """
        taken: list[Match] = []
        masked = text
        for detector in self.detectors:
            found = [m for m in detector.find(masked) if not self._allowed(m.value)]
            for match in found:
                taken.append(match)
                masked = (
                    masked[: match.start] + _MASK * (match.end - match.start) + masked[match.end :]
                )
        return sorted(taken, key=lambda m: m.start)

    def _allowed(self, value: str) -> bool:
        return value in self.allow or any(p.fullmatch(value) for p in self.allow_patterns)

    def replacement(self, match: Match) -> str:
        detector = match.detector
        if detector.action is Action.PSEUDONYMIZE:
            return self.pseudonymizer.pseudonym(detector.kind, detector.name, match.value)
        return f"[REDACTED:{detector.name}]"

    # -- whole text -------------------------------------------------------

    def redact(self, text: str, *, first_line: int = 1) -> RedactionResult:
        """Redact ``text``. Finding line numbers start at ``first_line``."""
        matches = self.matches(text)
        parts: list[str] = []
        findings: list[Finding] = []
        position = 0
        for match in matches:
            parts.append(text[position : match.start])
            parts.append(self.replacement(match))
            position = match.end
            line = first_line + text.count("\n", 0, match.start)
            column = match.start - (text.rfind("\n", 0, match.start) + 1) + 1
            findings.append(
                Finding(
                    detector=match.detector.name,
                    category=match.detector.category,
                    line=line,
                    column=column,
                    length=match.end - match.start,
                )
            )
        parts.append(text[position:])
        return RedactionResult("".join(parts), findings)

    # -- streaming --------------------------------------------------------

    def redact_lines(self, lines: Iterable[str]) -> Iterator[RedactionResult]:
        """Redact a stream of lines (with their line endings).

        Lines are processed one at a time, except that a private key block
        is buffered from its BEGIN line to its END line (up to
        :data:`MAX_BLOCK_LINES` lines) so it is caught as a whole. Each
        result holds the redacted text for one line or one block.
        """
        number = 0
        block: list[str] = []
        block_start = 0
        for line in lines:
            number += 1
            if block:
                block.append(line)
                if _BLOCK_END.search(line) or len(block) >= MAX_BLOCK_LINES:
                    yield self.redact("".join(block), first_line=block_start)
                    block = []
                continue
            start = _BLOCK_START.search(line)
            if start and not _BLOCK_END.search(line, start.end()):
                block = [line]
                block_start = number
                continue
            yield self.redact(line, first_line=number)
        if block:
            yield self.redact("".join(block), first_line=block_start)

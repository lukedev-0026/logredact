"""Built-in detectors for secrets and personal data.

Each :class:`Detector` is a regular expression plus an optional validator
that rejects look-alikes (a GitHub token with a bad checksum, a number that
fails the Luhn check, a string that is not a real IP address). Detectors are
listed in priority order: when two matches overlap, the earlier detector wins.
"""

from __future__ import annotations

import base64
import binascii
import enum
import ipaddress
import json
import re
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass

__all__ = [
    "BUILTIN_DETECTORS",
    "PSEUDONYM_EMAIL_DOMAIN",
    "PSEUDONYM_IPV4_NETWORK",
    "PSEUDONYM_IPV6_NETWORK",
    "Action",
    "Category",
    "Detector",
    "Match",
    "detector_by_name",
]

#: Pseudonyms are drawn from reserved ranges so they never collide with real
#: data and are not detected again when output is redacted a second time.
PSEUDONYM_EMAIL_DOMAIN = "redacted.invalid"
PSEUDONYM_IPV4_NETWORK = ipaddress.IPv4Network("240.0.0.0/4")
PSEUDONYM_IPV6_NETWORK = ipaddress.IPv6Network("2001:db8::/32")


class Category(enum.Enum):
    SECRET = "secret"
    PII = "pii"


class Action(enum.Enum):
    #: Replace with ``[REDACTED:<detector>]``.
    REDACT = "redact"
    #: Replace with a consistent pseudonym of the same shape.
    PSEUDONYMIZE = "pseudonymize"


@dataclass(frozen=True)
class Match:
    start: int
    end: int
    value: str
    detector: Detector


@dataclass(frozen=True)
class Detector:
    name: str
    category: Category
    description: str
    pattern: re.Pattern[str]
    #: Capture group holding the sensitive value (0 means the whole match).
    group: int = 0
    action: Action = Action.REDACT
    #: Shape of the pseudonym: "email", "ipv4", "ipv6" or "token".
    kind: str = "token"
    validate: Callable[[str], bool] | None = None

    def find(self, text: str) -> Iterator[Match]:
        for m in self.pattern.finditer(text):
            value = m.group(self.group)
            if not value:
                continue
            if self.validate is not None and not self.validate(value):
                continue
            start, end = m.span(self.group)
            yield Match(start, end, value, self)


# --- validators -----------------------------------------------------------

_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _base62(number: int, width: int) -> str:
    digits = ""
    while number:
        number, rest = divmod(number, 62)
        digits = _BASE62[rest] + digits
    return digits.rjust(width, "0")


def github_token_checksum_ok(token: str) -> bool:
    """Check the CRC32 checksum that ends every classic GitHub token."""
    body = token[4:]
    if len(body) != 36:
        return False
    return _base62(zlib.crc32(body[:30].encode()), 6) == body[30:]


def _jwt_ok(token: str) -> bool:
    header = token.split(".", 1)[0]
    try:
        decoded = base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))
        data = json.loads(decoded)
    except (binascii.Error, ValueError):
        return False
    return isinstance(data, dict) and ("alg" in data or "typ" in data)


def luhn_ok(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        n = int(char)
        if index % 2 == 1:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


_CARD_PREFIXES = re.compile(
    r"^(?:4|5[1-5]|2(?:2[2-9]|[3-6]\d|7[01]|720)|3[47]|3(?:0[0-5]|[68])|35|6011|64[4-9]|65)"
)


def _card_ok(text: str) -> bool:
    digits = re.sub(r"[ -]", "", text)
    return 13 <= len(digits) <= 19 and _CARD_PREFIXES.match(digits) is not None and luhn_ok(digits)


def _ipv4_ok(text: str) -> bool:
    try:
        address = ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return not (
        address.is_loopback
        or address.is_unspecified
        or address == ipaddress.IPv4Address("255.255.255.255")
        or address in PSEUDONYM_IPV4_NETWORK
    )


def _ipv6_ok(text: str) -> bool:
    try:
        address = ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return not (address.is_loopback or address.is_unspecified or address in PSEUDONYM_IPV6_NETWORK)


def _email_ok(text: str) -> bool:
    return not text.lower().endswith("@" + PSEUDONYM_EMAIL_DOMAIN)


_PLACEHOLDERS = {"null", "none", "nil", "true", "false", "undefined", "redacted", "changeme"}


def _assigned_secret_ok(value: str) -> bool:
    """Reject placeholders such as ``***``, ``${TOKEN}`` or ``<redacted>``."""
    lowered = value.lower()
    return not (
        lowered in _PLACEHOLDERS
        or set(value) <= set("*xX#.-_")
        or value.startswith(("${", "$(", "{{", "<", "[REDACTED", "%"))
        or lowered.startswith("redacted")
    )


# --- built-in detectors ---------------------------------------------------


def _d(
    name: str,
    category: Category,
    description: str,
    pattern: str,
    *,
    flags: int = 0,
    group: int = 0,
    action: Action = Action.REDACT,
    kind: str = "token",
    validate: Callable[[str], bool] | None = None,
) -> Detector:
    return Detector(
        name=name,
        category=category,
        description=description,
        pattern=re.compile(pattern, flags),
        group=group,
        action=action,
        kind=kind,
        validate=validate,
    )


S, P = Category.SECRET, Category.PII

BUILTIN_DETECTORS: tuple[Detector, ...] = (
    _d("private-key", S, "PEM private key blocks",
       r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
    _d("aws-access-key-id", S, "AWS access key IDs",
       r"(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}(?![A-Z0-9])"),
    _d("aws-secret-access-key", S, "AWS secret access keys next to their variable name",
       r"aws_?secret_?access_?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])",
       flags=re.IGNORECASE, group=1),
    _d("github-token", S, "GitHub classic tokens (checksum verified)",
       r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36}(?![A-Za-z0-9_])",
       validate=github_token_checksum_ok),
    _d("github-fine-grained-token", S, "GitHub fine-grained personal access tokens",
       r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}(?![A-Za-z0-9_])"),
    _d("gitlab-token", S, "GitLab personal access tokens",
       r"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20}(?![A-Za-z0-9_-])"),
    _d("slack-token", S, "Slack bot, user and app tokens",
       r"(?<![A-Za-z0-9-])xox[abposr]-[A-Za-z0-9-]{10,}"),
    _d("slack-webhook", S, "Slack incoming-webhook URLs",
       r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+"),
    _d("stripe-key", S, "Stripe secret and restricted keys",
       r"(?<![A-Za-z0-9_])[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"),
    _d("google-api-key", S, "Google API keys",
       r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"),
    _d("jwt", S, "JSON Web Tokens",
       r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*",
       validate=_jwt_ok),
    _d("authorization-header", S, "Credentials in Authorization headers",
       r"\b(?:proxy-)?authorization[\"']?\s*[:=]\s*[\"']?(?:bearer|basic|token|digest)\s+"
       r"([A-Za-z0-9._~+/=-]{8,})",
       flags=re.IGNORECASE, group=1),
    _d("url-credentials", S, "Passwords embedded in URLs (scheme://user:password@host)",
       r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@]+:([^\s/@]+)@", group=1),
    _d("assigned-secret", S, "Values assigned to names like password, secret, api_key or token",
       r"(?<![A-Za-z0-9])(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token"
       r"|auth[_-]?token|refresh[_-]?token|token)[\"']?\s*[:=]\s*[\"']?([^\s\"',;&]{4,})",
       flags=re.IGNORECASE, group=1, validate=_assigned_secret_ok),
    _d("card-number", P, "Payment card numbers (prefix and Luhn verified)",
       r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])", validate=_card_ok),
    _d("email", P, "Email addresses",
       r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![A-Za-z0-9-])",
       action=Action.PSEUDONYMIZE, kind="email", validate=_email_ok),
    _d("ipv4", P, "IPv4 addresses (loopback and unspecified are kept)",
       r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)",
       action=Action.PSEUDONYMIZE, kind="ipv4", validate=_ipv4_ok),
    _d("ipv6", P, "IPv6 addresses (loopback and unspecified are kept)",
       r"(?<![0-9A-Za-z:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Za-z:])",
       action=Action.PSEUDONYMIZE, kind="ipv6", validate=_ipv6_ok),
)  # fmt: skip


def detector_by_name(name: str) -> Detector:
    for detector in BUILTIN_DETECTORS:
        if detector.name == name:
            return detector
    raise KeyError(name)

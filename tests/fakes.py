"""Synthetic credentials for tests.

None of these are real. They are assembled at runtime from fragments so
that no complete token-shaped string appears in the repository, which keeps
secret scanners (including GitHub push protection) quiet.
"""

from __future__ import annotations

import base64
import json
import random
import string
import zlib

_ALNUM = string.ascii_letters + string.digits
_BASE62 = string.digits + string.ascii_uppercase + string.ascii_lowercase


def _base62(number: int, width: int) -> str:
    out = ""
    while number:
        number, rest = divmod(number, 62)
        out = _BASE62[rest] + out
    return out.rjust(width, "0")


def github_token(seed: int = 1, prefix: str = "ghp") -> str:
    body = "".join(random.Random(seed).choice(_ALNUM) for _ in range(30))
    return prefix + "_" + body + _base62(zlib.crc32(body.encode()), 6)


def github_token_bad_checksum(seed: int = 1) -> str:
    token = github_token(seed)
    last = "A" if token[-1] != "A" else "B"
    return token[:-1] + last


def aws_access_key_id() -> str:
    # AWS's own documentation example key ID.
    return "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"


def aws_secret_access_key() -> str:
    # AWS's own documentation example secret key.
    return "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"


def github_fine_grained_token() -> str:
    return "github" + "_pat_" + "A" * 22 + "_" + "b" * 59


def gitlab_token() -> str:
    return "gl" + "pat-" + "x1y2z3" * 3 + "ab"


def slack_token() -> str:
    return "xo" + "xb-" + "000000000000-000000000000-" + "a" * 24


def slack_webhook() -> str:
    return "https://hooks.slack.com" + "/services/T0000/B0000/" + "X" * 24


def stripe_key() -> str:
    return "sk" + "_test_" + "0" * 24


def google_api_key() -> str:
    return "AI" + "za" + "Sy" + "0" * 33


def jwt(payload: dict[str, object] | None = None) -> str:
    def part(data: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    return part({"alg": "HS256", "typ": "JWT"}) + "." + part(payload or {"sub": "1"}) + ".c2ln"


def private_key_block() -> str:
    kind = "RSA " + "PRIVATE KEY"
    body = "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX\n6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu"
    return f"-----BEGIN {kind}-----\n{body}\n-----END {kind}-----"

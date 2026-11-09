"""Consistent, keyed pseudonyms.

The same input value and key always produce the same pseudonym, so a log
stays readable ("the same user failed three times") without revealing who.
Pseudonyms are an HMAC-SHA256 of the value, so without the key they cannot
be reversed or confirmed by guessing likely values.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets

from logredact.detectors import (
    PSEUDONYM_EMAIL_DOMAIN,
    PSEUDONYM_IPV4_NETWORK,
    PSEUDONYM_IPV6_NETWORK,
)

__all__ = ["Pseudonymizer"]

_MIN_KEY_BYTES = 16


class Pseudonymizer:
    """Map values to pseudonyms with a secret key.

    Without a key a random one is generated, so pseudonyms are consistent
    within one run but cannot be linked across runs.
    """

    def __init__(self, key: bytes | None = None) -> None:
        if key is not None and len(key) < _MIN_KEY_BYTES:
            raise ValueError(f"pseudonym key must be at least {_MIN_KEY_BYTES} bytes")
        self._key = key if key is not None else secrets.token_bytes(32)

    def digest(self, kind: str, value: str) -> bytes:
        message = f"{kind}\x00{value}".encode("utf-8", "surrogateescape")
        return hmac.new(self._key, message, hashlib.sha256).digest()

    def pseudonym(self, kind: str, label: str, value: str) -> str:
        """Return the pseudonym for ``value``.

        ``kind`` selects the shape: ``email``, ``ipv4``, ``ipv6`` or
        anything else for a ``<label>-<hex>`` token.
        """
        if kind == "email":
            digest = self.digest(kind, value.lower())
            return f"user-{digest.hex()[:10]}@{PSEUDONYM_EMAIL_DOMAIN}"
        digest = self.digest(kind, value)
        number = int.from_bytes(digest, "big")
        if kind == "ipv4":
            # 240.0.0.0/4 minus its last address, 255.255.255.255 (broadcast).
            span = PSEUDONYM_IPV4_NETWORK.num_addresses - 1
            return str(PSEUDONYM_IPV4_NETWORK.network_address + number % span)
        if kind == "ipv6":
            span = PSEUDONYM_IPV6_NETWORK.num_addresses
            address = PSEUDONYM_IPV6_NETWORK.network_address + number % span
            return str(ipaddress.IPv6Address(address))
        return f"{label}-{digest.hex()[:10]}"

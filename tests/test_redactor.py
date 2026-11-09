import ipaddress

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from fakes import github_token, jwt, private_key_block
from logredact.detectors import BUILTIN_DETECTORS, Category
from logredact.pseudonym import Pseudonymizer
from logredact.redactor import MAX_BLOCK_LINES, Redactor

KEY = b"k" * 32


def redactor(**kwargs: object) -> Redactor:
    return Redactor(key=KEY, **kwargs)  # type: ignore[arg-type]


def test_redacts_secret_and_pseudonymizes_pii() -> None:
    token = github_token()
    result = redactor().redact(f"user bob@example.com pushed with {token} from 198.51.100.7")
    assert token not in result.text
    assert "bob@example.com" not in result.text
    assert "198.51.100.7" not in result.text
    assert "[REDACTED:github-token]" in result.text
    assert "@redacted.invalid" in result.text
    assert [f.detector for f in result.findings] == ["email", "github-token", "ipv4"]


def test_pseudonyms_are_consistent_and_keyed() -> None:
    a = redactor().redact("a@example.com a@example.com A@EXAMPLE.COM b@example.com").text
    names = a.split()
    assert names[0] == names[1] == names[2]
    assert names[3] != names[0]
    other = Redactor(key=b"z" * 32).redact("a@example.com").text
    assert other != names[0]


def test_random_key_differs_between_instances() -> None:
    assert Redactor().redact("10.1.2.3").text != Redactor().redact("10.1.2.3").text


def test_pseudonym_shapes() -> None:
    p = Pseudonymizer(KEY)
    ipv4 = ipaddress.IPv4Address(p.pseudonym("ipv4", "ipv4", "10.0.0.1"))
    assert ipv4 in ipaddress.IPv4Network("240.0.0.0/4")
    assert ipv4 != ipaddress.IPv4Address("255.255.255.255")
    ipv6 = ipaddress.IPv6Address(p.pseudonym("ipv6", "ipv6", "fe80::1"))
    assert ipv6 in ipaddress.IPv6Network("2001:db8::/32")
    assert p.pseudonym("token", "customer-id", "C-1").startswith("customer-id-")


def test_short_key_rejected() -> None:
    with pytest.raises(ValueError, match="at least 16 bytes"):
        Pseudonymizer(b"short")


def test_findings_have_positions_but_not_values() -> None:
    result = redactor().redact("line one\n  password=hunter22\n")
    (finding,) = result.findings
    assert (finding.line, finding.column, finding.length) == (2, 12, 8)
    assert finding.category is Category.SECRET
    assert "hunter22" not in repr(finding)


def test_overlap_prefers_earlier_detector() -> None:
    # A JWT inside an Authorization header is reported once, as a JWT.
    token = jwt()
    result = redactor().redact(f"Authorization: Bearer {token}")
    assert [f.detector for f in result.findings] == ["jwt"]
    # A URL password wins over the email-shaped text that contains it.
    result = redactor().redact("https://deploy:pa55w0rd@git.example.com/repo")
    assert [f.detector for f in result.findings] == ["url-credentials"]
    assert "pa55w0rd" not in result.text


def test_allowlists() -> None:
    r = redactor(allow=["ops@example.com"], allow_patterns=[r"10\..*"])
    text = "ops@example.com dev@example.com 10.0.0.5 192.0.2.1"
    out = r.redact(text).text
    assert "ops@example.com" in out and "10.0.0.5" in out
    assert "dev@example.com" not in out and "192.0.2.1" not in out


def test_custom_detector_order() -> None:
    email_only = [d for d in BUILTIN_DETECTORS if d.name == "email"]
    out = Redactor(email_only, key=KEY).redact("x@example.com 10.0.0.1").text
    assert "10.0.0.1" in out


def test_streaming_matches_line_numbers_and_endings() -> None:
    lines = ["ok\r\n", "ip 10.0.0.9\r\n", "done"]
    results = list(redactor().redact_lines(lines))
    assert len(results) == 3
    assert results[0].text == "ok\r\n"
    assert results[1].text.endswith("\r\n")
    assert results[1].findings[0].line == 2
    assert results[2].text == "done"


def test_streaming_catches_multiline_private_key() -> None:
    block = private_key_block()
    lines = ["before\n", *[line + "\n" for line in block.splitlines()], "after\n"]
    results = list(redactor().redact_lines(lines))
    joined = "".join(r.text for r in results)
    assert joined == "before\n[REDACTED:private-key]\nafter\n"
    (finding,) = [f for r in results for f in r.findings]
    assert finding.line == 2


def test_unterminated_key_block_is_flushed() -> None:
    lines = ["-----BEGIN " + "PRIVATE KEY-----\n"] + ["AAAA\n"] * (MAX_BLOCK_LINES + 5)
    results = list(redactor().redact_lines(lines))
    assert "".join(r.text for r in results) == "".join(lines)


_log_text = st.lists(
    st.one_of(
        st.text(alphabet=st.characters(codec="utf-8"), max_size=30),
        st.sampled_from(
            ["bob@example.com", "10.20.30.40", "fe80::1:2", "password=hunter22",
             "4111 1111 1111 1111", "https://u:pw1234@db.example",
             "Authorization: Bearer abcdefgh1", "token=Zt9qL2xw w", " ", "\n", ":", "@", "."]
        ),
    ),
    max_size=12,
).map("".join)  # fmt: skip


@settings(max_examples=300, deadline=None)
@given(_log_text)
def test_redaction_is_idempotent(text: str) -> None:
    r = redactor()
    once = r.redact(text).text
    assert r.redact(once).text == once


@settings(max_examples=300, deadline=None)
@given(_log_text)
def test_streaming_equals_whole_text_for_single_lines(text: str) -> None:
    line = text.replace("\n", " ").replace("\r", " ")
    r = redactor()
    assert "".join(x.text for x in r.redact_lines([line])) == r.redact(line).text


def test_check_is_clean_after_redaction() -> None:
    r = redactor()
    once = r.redact("postgres://app:s3cret@db.internal/x password=hunter22").text
    assert r.redact(once).findings == []


@settings(max_examples=300, deadline=None)
@given(_log_text)
def test_second_pass_finds_nothing(text: str) -> None:
    r = redactor()
    assert r.redact(r.redact(text).text).findings == []


def test_masked_value_does_not_extend_into_following_words() -> None:
    out = redactor().redact("GET /api?token=Zt9qL2xw from 198.51.100.23 by x").text
    assert out.startswith("GET /api?token=[REDACTED:assigned-secret] from 2")
    assert out.endswith(" by x")


def test_nul_in_input_does_not_break_output() -> None:
    text = "a\x00b password=hunter22 \x00"
    assert redactor().redact(text).text == "a\x00b password=[REDACTED:assigned-secret] \x00"

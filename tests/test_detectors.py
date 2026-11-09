import pytest

from fakes import (
    aws_access_key_id,
    aws_secret_access_key,
    github_fine_grained_token,
    github_token,
    github_token_bad_checksum,
    gitlab_token,
    google_api_key,
    jwt,
    private_key_block,
    slack_token,
    slack_webhook,
    stripe_key,
)
from logredact.detectors import (
    BUILTIN_DETECTORS,
    Category,
    detector_by_name,
    github_token_checksum_ok,
    luhn_ok,
)


def values(name: str, text: str) -> list[str]:
    return [m.value for m in detector_by_name(name).find(text)]


def test_names_unique_and_lookup() -> None:
    names = [d.name for d in BUILTIN_DETECTORS]
    assert len(names) == len(set(names))
    with pytest.raises(KeyError):
        detector_by_name("nope")


def test_categories() -> None:
    assert detector_by_name("github-token").category is Category.SECRET
    assert detector_by_name("email").category is Category.PII


@pytest.mark.parametrize(
    ("name", "make", "template"),
    [
        ("aws-access-key-id", aws_access_key_id, "key={}"),
        ("github-token", github_token, "token: {} "),
        ("github-fine-grained-token", github_fine_grained_token, "PAT={}"),
        ("gitlab-token", gitlab_token, "using {}"),
        ("slack-token", slack_token, "slack {}"),
        ("slack-webhook", slack_webhook, "posting to {} now"),
        ("stripe-key", stripe_key, "stripe={}"),
        ("google-api-key", google_api_key, "?key={}&q=1"),
        ("jwt", jwt, "session {}"),
        ("private-key", private_key_block, "key:\n{}\nend"),
    ],
)
def test_token_detectors_find_whole_token(name: str, make: object, template: str) -> None:
    token = make()  # type: ignore[operator]
    assert values(name, template.format(token)) == [token]


def test_github_checksum() -> None:
    assert github_token_checksum_ok(github_token(7))
    assert not github_token_checksum_ok(github_token_bad_checksum(7))
    assert values("github-token", github_token_bad_checksum(3)) == []
    for prefix in ("gho", "ghu", "ghs", "ghr"):
        assert values("github-token", github_token(5, prefix)) == [github_token(5, prefix)]


def test_aws_secret_needs_its_name() -> None:
    secret = aws_secret_access_key()
    assert values("aws-secret-access-key", f"AWS_SECRET_ACCESS_KEY={secret}") == [secret]
    assert values("aws-secret-access-key", f'"aws_secret_access_key": "{secret}"') == [secret]
    assert values("aws-secret-access-key", f"random={secret}") == []


def test_jwt_requires_json_header() -> None:
    assert values("jwt", "eyJub3RqcGVn.eyJzdWIiOiIxIn0.sig") == []


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Authorization: Bearer abc.def-ghi_123", ["abc.def-ghi_123"]),
        ('"authorization": "Basic dXNlcjpwYXNzd29yZA=="', ["dXNlcjpwYXNzd29yZA=="]),
        ("Proxy-Authorization: token 0123456789", ["0123456789"]),
        ("Authorization: Bearer short", []),
    ],
)
def test_authorization_header(text: str, expected: list[str]) -> None:
    assert values("authorization-header", text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("postgres://app:s3cr3t-pw@db.internal:5432/app", ["s3cr3t-pw"]),
        ("redis://default:hunter22@cache:6379", ["hunter22"]),
        ("https://example.com/path:with@sign", []),
        ("https://user@example.com", []),
    ],
)
def test_url_credentials(text: str, expected: list[str]) -> None:
    assert values("url-credentials", text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("password=hunter22", ["hunter22"]),
        ('{"api_key": "abcd1234efgh"}', ["abcd1234efgh"]),
        ("DB_PASSWORD: 'pa55word!'", ["pa55word!"]),
        ("client_secret=Zx9_Q", ["Zx9_Q"]),
        ("refresh-token = rt.abcdef", ["rt.abcdef"]),
        ("password=***", []),
        ("password=${DB_PASSWORD}", []),
        ("token: null", []),
        ("password=<redacted>", []),
        ("passwords are hashed", []),
        ("password=abc", []),
    ],
)
def test_assigned_secret(text: str, expected: list[str]) -> None:
    assert values("assigned-secret", text) == expected


@pytest.mark.parametrize(
    ("text", "found"),
    [
        ("card 4111 1111 1111 1111 ok", True),
        ("card 4111-1111-1111-1111", True),
        ("5555555555554444", True),
        ("378282246310005", True),
        ("4111111111111112", False),  # fails Luhn
        ("1234567812345670", False),  # passes Luhn, unknown prefix
        ("order 12345", False),
        ("id 9b2c4e7a-1111-4111-8111-111111111111", False),
    ],
)
def test_card_numbers(text: str, found: bool) -> None:
    assert bool(values("card-number", text)) is found


def test_luhn() -> None:
    assert luhn_ok("79927398713")
    assert not luhn_ok("79927398710")


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("from alice.smith+tag@mail.example.co.uk.", ["alice.smith+tag@mail.example.co.uk"]),
        ("<bob@example.org>", ["bob@example.org"]),
        ("user-0a1b2c3d4e@redacted.invalid", []),
        ("not an email: a@b", []),
    ],
)
def test_email(text: str, expected: list[str]) -> None:
    assert values("email", text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("client 203.0.113.9 connected", ["203.0.113.9"]),
        ("10.0.0.1:8080", ["10.0.0.1"]),
        ("at 192.168.1.20.", ["192.168.1.20"]),
        ("127.0.0.1 and 0.0.0.0", []),
        ("version 1.2.3.4.5", []),
        ("999.1.1.1", []),
        ("241.10.20.30", []),  # pseudonym range
    ],
)
def test_ipv4(text: str, expected: list[str]) -> None:
    assert values("ipv4", text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("peer fe80::1ff:fe23:4567:890a closed", ["fe80::1ff:fe23:4567:890a"]),
        ("[2a02:6b8::feed:bad]:443", ["2a02:6b8::feed:bad"]),
        ("::1 and ::", []),
        ("at 12:34:56", []),
        ("mac aa:bb:cc:dd:ee:ff", []),
        ("std::vector<int>", []),
        ("2001:db8::42", []),  # pseudonym range
    ],
)
def test_ipv6(text: str, expected: list[str]) -> None:
    assert values("ipv6", text) == expected

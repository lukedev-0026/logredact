from pathlib import Path

import pytest

from logredact.cli import run

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
DEMO_KEY = "demo-key-not-secret-0001"


def test_sample_log_matches_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOGREDACT_KEY", DEMO_KEY)
    out = tmp_path / "out.log"
    code = run(
        ["--config", str(EXAMPLES / "logredact.toml"), str(EXAMPLES / "sample.log"), "-o", str(out)]
    )
    assert code == 0
    expected = (EXAMPLES / "sample.redacted.log").read_bytes()
    assert out.read_bytes() == expected


@pytest.mark.parametrize(
    "secret",
    [
        "maria.lopez@example.com",
        "203.0.113.24",
        "198.51.100.77",
        "fd00:1:2::8a2e:370:7334",
        "Tr0ub4dor-3",
        "4111 1111 1111 1111",
        "ORD-48213",
        "dGhpcy1pcy1ub3QtYS1yZWFsLXRva2Vu",
        "correct-horse-battery",
    ],
)
def test_snapshot_contains_no_original_values(secret: str) -> None:
    assert secret in (EXAMPLES / "sample.log").read_text()
    assert secret not in (EXAMPLES / "sample.redacted.log").read_text()


def test_loopback_is_kept() -> None:
    assert "127.0.0.1:8080" in (EXAMPLES / "sample.redacted.log").read_text()

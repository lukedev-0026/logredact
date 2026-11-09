import io
import json
from pathlib import Path

import pytest

from fakes import github_token, private_key_block
from logredact import __version__
from logredact.cli import run

KEY = "a-test-key-of-sufficient-length"


@pytest.fixture(autouse=True)
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LOGREDACT_KEY", raising=False)
    return tmp_path


def call(*args: str, stdin: bytes = b"") -> tuple[int, bytes, str]:
    out, err = io.BytesIO(), io.StringIO()
    code = run(list(args), stdin=io.BytesIO(stdin), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_stdin_to_stdout() -> None:
    token = github_token()
    code, out, _ = call(stdin=f"push {token} by eve@example.com\n".encode())
    assert code == 0
    text = out.decode()
    assert "[REDACTED:github-token]" in text
    assert "eve@example.com" not in text
    assert text.endswith("@redacted.invalid\n")


def test_preserves_crlf_and_undecodable_bytes() -> None:
    raw = b"ok \xff\xfe\r\npassword=hunter22\r\n"
    code, out, _ = call(stdin=raw)
    assert code == 0
    assert out == b"ok \xff\xfe\r\npassword=[REDACTED:assigned-secret]\r\n"


def test_key_makes_pseudonyms_stable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOGREDACT_KEY", KEY)
    first = call(stdin=b"10.0.0.7\n")[1]
    second = call(stdin=b"10.0.0.7\n")[1]
    assert first == second
    monkeypatch.setenv("OTHER_KEY", KEY + "-other")
    assert call("--key-env", "OTHER_KEY", stdin=b"10.0.0.7\n")[1] != first


def test_missing_and_short_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    code, _, err = call("--key-env", "NOT_SET_ANYWHERE")
    assert code == 2 and "NOT_SET_ANYWHERE is not set" in err
    monkeypatch.setenv("LOGREDACT_KEY", "short")
    code, _, err = call(stdin=b"x\n")
    assert code == 2 and "at least 16 bytes" in err


def test_files_and_output(isolated: Path) -> None:
    (isolated / "a.log").write_text("a 192.0.2.10\n", encoding="utf-8")
    (isolated / "b.log").write_text(private_key_block() + "\nb\n", encoding="utf-8")
    code, out, err = call("a.log", "b.log", "-o", "safe.log", "--stats")
    assert code == 0 and out == b""
    safe = (isolated / "safe.log").read_text(encoding="utf-8")
    assert "192.0.2.10" not in safe
    assert safe.endswith("[REDACTED:private-key]\nb\n")
    assert "redacted 2 value(s): " in err


def test_output_must_not_be_input(isolated: Path) -> None:
    (isolated / "a.log").write_text("x\n")
    code, _, err = call("a.log", "-o", "a.log")
    assert code == 2 and "also an input" in err
    assert (isolated / "a.log").read_text() == "x\n"


def test_missing_file() -> None:
    code, _, err = call("nope.log")
    assert code == 2 and "nope.log: no such file" in err


def test_check_text_and_json(isolated: Path) -> None:
    (isolated / "app.log").write_text("fine\nAuthorization: Bearer abcdefgh123\n")
    code, out, _ = call("--check", "app.log")
    assert code == 1
    assert out.decode().splitlines() == [
        "app.log:2:23: authorization-header (secret)",
        "1 sensitive value(s) found.",
    ]
    assert b"abcdefgh123" not in out
    code, out, _ = call("--check", "--format", "json", "app.log")
    data = json.loads(out)
    assert code == 1 and data["total"] == 1
    assert data["findings"][0] == {
        "path": "app.log", "line": 2, "column": 23, "length": 11,
        "detector": "authorization-header", "category": "secret",
    }  # fmt: skip


def test_check_clean() -> None:
    assert call("--check", stdin=b"nothing to see\n") == (0, b"Nothing found.\n", "")


def test_disable_and_allow() -> None:
    _, out, _ = call("--disable", "ipv4", "--allow", "ops@example.com",
                     stdin=b"10.1.1.1 ops@example.com x@example.com\n")  # fmt: skip
    text = out.decode()
    assert text.startswith("10.1.1.1 ops@example.com user-")
    code, _, err = call("--disable", "nope")
    assert code == 2 and "unknown detector(s) nope" in err


def test_config_file_rules(isolated: Path) -> None:
    (isolated / "logredact.toml").write_text(
        '[[rules]]\nname = "order-id"\npattern = "ORD-[0-9]{5}"\n'
    )
    _, out, _ = call(stdin=b"order ORD-12345 shipped\n")
    assert out == b"order [REDACTED:order-id] shipped\n"
    (isolated / "logredact.toml").write_text("oops = 1\n")
    code, _, err = call(stdin=b"x")
    assert code == 2 and "unknown setting(s): oops" in err


def test_list_detectors() -> None:
    code, out, _ = call("--list-detectors")
    lines = out.decode().splitlines()
    assert code == 0
    assert lines[0].startswith("private-key")
    assert any(line.startswith("email ") and "pseudonymize" in line for line in lines)


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as info:
        run(["--version"])
    assert info.value.code == 0
    assert __version__ in capsys.readouterr().out

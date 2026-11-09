from pathlib import Path

import pytest

from logredact.config import (
    Config,
    ConfigError,
    build_detectors,
    find_config,
    load_config,
    parse_settings,
)
from logredact.detectors import BUILTIN_DETECTORS, Action, Category
from logredact.redactor import Redactor


def test_defaults() -> None:
    config = parse_settings({})
    assert config == Config()
    assert build_detectors(config) == BUILTIN_DETECTORS


def test_custom_rule_runs_first_and_pseudonymizes() -> None:
    config = parse_settings(
        {
            "rules": [
                {
                    "name": "customer-id",
                    "pattern": r"customer=(CUST-\d{6})",
                    "group": 1,
                    "action": "pseudonymize",
                    "category": "pii",
                }
            ]
        }
    )
    (rule,) = config.rules
    assert (rule.action, rule.category, rule.group) == (Action.PSEUDONYMIZE, Category.PII, 1)
    detectors = build_detectors(config)
    assert detectors[0].name == "customer-id"
    out = Redactor(detectors, key=b"x" * 16).redact("customer=CUST-123456 ok").text
    assert out.startswith("customer=customer-id-")
    assert "CUST-123456" not in out


def test_disable_and_extra_disable() -> None:
    config = parse_settings({"disable": ["ipv4"]})
    names = [d.name for d in build_detectors(config, ("email",))]
    assert "ipv4" not in names and "email" not in names
    with pytest.raises(ConfigError, match="unknown detector"):
        build_detectors(config, ("nope",))


def test_allow_patterns_compiled() -> None:
    config = parse_settings({"allow": ["a@b.co"], "allow-patterns": [r"10\..*"]})
    assert config.allow == ("a@b.co",)
    assert config.allow_patterns[0].fullmatch("10.1.2.3")


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"colour": 1}, "unknown setting(s): colour"),
        ({"disable": ["nope"]}, "unknown detector(s) nope"),
        ({"disable": "ipv4"}, "disable must be a list"),
        ({"allow": [1]}, "allow must be a list of strings"),
        ({"allow-patterns": ["("]}, "allow-patterns"),
        ({"key-env": "1BAD"}, "key-env must be an environment variable name"),
        ({"rules": ["x"]}, "rules[0] must be a table"),
        ({"rules": [{"name": "Bad Name", "pattern": "x"}]}, "name must be lowercase"),
        ({"rules": [{"name": "r", "pattern": ""}]}, "pattern must be a non-empty string"),
        ({"rules": [{"name": "r", "pattern": "("}]}, "invalid pattern"),
        ({"rules": [{"name": "r", "pattern": "(a)", "group": 2}]}, "group must be 0-1"),
        ({"rules": [{"name": "r", "pattern": "a", "action": "hide"}]}, "action must be"),
        ({"rules": [{"name": "r", "pattern": "a", "colour": 1}]}, "unknown key(s): colour"),
        ({"rules": [{"name": "email", "pattern": "a"}]}, "already used: email"),
        (
            {"rules": [{"name": "r", "pattern": "a"}, {"name": "r", "pattern": "b"}]},
            "already used: r",
        ),
    ],
)
def test_invalid_settings(data: dict[str, object], message: str) -> None:
    with pytest.raises(ConfigError) as info:
        parse_settings(data)
    assert message in str(info.value)


def test_files(tmp_path: Path) -> None:
    (tmp_path / "logredact.toml").write_text('disable = ["ipv6"]\n')
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    found = find_config(nested)
    assert found == (tmp_path / "logredact.toml").resolve()
    assert load_config(found).disable == ("ipv6",)

    pyproject = tmp_path / "a" / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "x"\n\n[[tool.logredact.rules]]\nname = "r"\npattern = "zz"\n'
    )
    assert find_config(nested) == pyproject.resolve()
    assert load_config(pyproject).rules[0].name == "r"

    (tmp_path / "bad.toml").write_text("disable = [\n")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(tmp_path / "bad.toml")

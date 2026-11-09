"""Settings from ``logredact.toml`` or ``[tool.logredact]`` in ``pyproject.toml``.

Example::

    disable = ["ipv4"]
    allow = ["support@example.com"]
    allow-patterns = ['10\\..*']
    key-env = "LOGREDACT_KEY"

    [[rules]]
    name = "customer-id"
    pattern = 'CUST-\\d{6}'
    action = "pseudonymize"   # or "redact" (default)
    category = "pii"          # or "secret" (default)
    group = 0                 # capture group holding the value
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from logredact.detectors import BUILTIN_DETECTORS, Action, Category, Detector

__all__ = [
    "DEFAULT_KEY_ENV",
    "Config",
    "ConfigError",
    "build_detectors",
    "find_config",
    "load_config",
    "parse_settings",
]

CONFIG_FILE = "logredact.toml"
DEFAULT_KEY_ENV = "LOGREDACT_KEY"
_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")


class ConfigError(ValueError):
    """Raised for settings that cannot be used."""


@dataclass(frozen=True)
class Config:
    disable: tuple[str, ...] = ()
    allow: tuple[str, ...] = ()
    allow_patterns: tuple[re.Pattern[str], ...] = ()
    rules: tuple[Detector, ...] = ()
    key_env: str = DEFAULT_KEY_ENV
    source: Path | None = None


def find_config(start: Path) -> Path | None:
    """Return the nearest ``logredact.toml``, or ``pyproject.toml`` with a logredact table."""
    for directory in [start.resolve(), *start.resolve().parents]:
        candidate = directory / CONFIG_FILE
        if candidate.is_file():
            return candidate
        pyproject = directory / "pyproject.toml"
        if pyproject.is_file() and "logredact" in _read_toml(pyproject).get("tool", {}):
            return pyproject
    return None


def load_config(path: Path) -> Config:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc
    if path.name == "pyproject.toml":
        data = data.get("tool", {}).get("logredact", {})
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: logredact settings must be a table")
    return parse_settings(data, path)


def parse_settings(data: dict[str, Any], source: Path | None = None) -> Config:
    where = f"{source}: " if source else ""
    unknown = sorted(set(data) - {"disable", "allow", "allow-patterns", "key-env", "rules"})
    if unknown:
        raise ConfigError(f"{where}unknown setting(s): {', '.join(unknown)}")

    rules = tuple(
        _parse_rule(raw, index, where) for index, raw in enumerate(_list(data, "rules", where))
    )
    builtin_names = {d.name for d in BUILTIN_DETECTORS}
    names = [r.name for r in rules]
    clashes = sorted({n for n in names if names.count(n) > 1 or n in builtin_names})
    if clashes:
        raise ConfigError(f"{where}rule name(s) already used: {', '.join(clashes)}")

    disable = _strings(data, "disable", where)
    unknown_detectors = sorted(set(disable) - builtin_names - set(names))
    if unknown_detectors:
        raise ConfigError(f"{where}disable: unknown detector(s) {', '.join(unknown_detectors)}")

    patterns = []
    for text in _strings(data, "allow-patterns", where):
        try:
            patterns.append(re.compile(text))
        except re.error as exc:
            raise ConfigError(f"{where}allow-patterns: {text!r}: {exc}") from exc

    key_env = data.get("key-env", DEFAULT_KEY_ENV)
    if not isinstance(key_env, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key_env):
        raise ConfigError(f"{where}key-env must be an environment variable name")

    return Config(
        disable=disable,
        allow=_strings(data, "allow", where),
        allow_patterns=tuple(patterns),
        rules=rules,
        key_env=key_env,
        source=source,
    )


def build_detectors(config: Config, extra_disable: tuple[str, ...] = ()) -> tuple[Detector, ...]:
    """Custom rules first (highest priority), then the enabled built-ins."""
    disabled = set(config.disable) | set(extra_disable)
    known = {d.name for d in BUILTIN_DETECTORS} | {r.name for r in config.rules}
    unknown = sorted(set(extra_disable) - known)
    if unknown:
        raise ConfigError(f"unknown detector(s) {', '.join(unknown)}")
    return tuple(d for d in (*config.rules, *BUILTIN_DETECTORS) if d.name not in disabled)


def _parse_rule(raw: object, index: int, where: str) -> Detector:
    label = f"{where}rules[{index}]"
    if not isinstance(raw, dict):
        raise ConfigError(f"{label} must be a table")
    unknown = sorted(set(raw) - {"name", "pattern", "action", "category", "group", "description"})
    if unknown:
        raise ConfigError(f"{label}: unknown key(s): {', '.join(unknown)}")

    name = raw.get("name")
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise ConfigError(f"{label}: name must be lowercase letters, digits and hyphens")
    text = raw.get("pattern")
    if not isinstance(text, str) or not text:
        raise ConfigError(f"{label} ({name}): pattern must be a non-empty string")
    try:
        pattern = re.compile(text)
    except re.error as exc:
        raise ConfigError(f"{label} ({name}): invalid pattern: {exc}") from exc
    group = raw.get("group", 0)
    if isinstance(group, bool) or not isinstance(group, int) or not 0 <= group <= pattern.groups:
        raise ConfigError(f"{label} ({name}): group must be 0-{pattern.groups}")
    try:
        action = Action(raw.get("action", "redact"))
        category = Category(raw.get("category", "secret"))
    except ValueError:
        raise ConfigError(
            f"{label} ({name}): action must be redact or pseudonymize, "
            "category must be secret or pii"
        ) from None
    description = raw.get("description", f"Custom rule {name}")
    if not isinstance(description, str):
        raise ConfigError(f"{label} ({name}): description must be a string")
    return Detector(
        name=name,
        category=category,
        description=description,
        pattern=pattern,
        group=group,
        action=action,
        kind="token",
    )


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return {}


def _list(data: dict[str, Any], key: str, where: str) -> list[Any]:
    value = data.get(key, [])
    if not isinstance(value, list):
        raise ConfigError(f"{where}{key} must be a list")
    return value


def _strings(data: dict[str, Any], key: str, where: str) -> tuple[str, ...]:
    value = _list(data, key, where)
    if not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where}{key} must be a list of strings")
    return tuple(value)

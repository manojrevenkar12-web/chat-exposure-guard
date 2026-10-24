"""Settings and rule families, read from ``config/``."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

# The directory holding config/, rules/ and migrations/: the checkout, or CEG_HOME in an image.
ROOT = Path(os.environ.get("CEG_HOME") or Path(__file__).resolve().parents[2])
CONFIG_DIR = Path(os.environ.get("CEG_CONFIG_DIR", ROOT / "config"))


@dataclass(frozen=True)
class Settings:
    sla_days: dict[str, int]
    raise_if_exposed_with: frozenset[str]
    lower_if_internal_without_sensitive: bool
    never_lower: frozenset[str]
    max_risk_acceptance_days: int
    same_symbol_line_window: int
    render_allowlist: tuple[str, ...]
    link_allowlist: tuple[str, ...]
    fetch_allowlist: tuple[str, ...]
    ignore_rules: frozenset[str] = frozenset()


@lru_cache(maxsize=4)
def load_settings(config_dir: str | None = None) -> Settings:
    d = Path(config_dir) if config_dir else CONFIG_DIR
    raw: dict[str, Any] = yaml.safe_load((d / "settings.yaml").read_text())
    ctx = raw["context"]
    return Settings(
        sla_days={k: int(v) for k, v in raw["sla_days"].items()},
        raise_if_exposed_with=frozenset(ctx["raise_if_exposed_with"]),
        lower_if_internal_without_sensitive=bool(ctx["lower_if_internal_without_sensitive"]),
        never_lower=frozenset(ctx["never_lower"]),
        max_risk_acceptance_days=int(raw["max_risk_acceptance_days"]),
        same_symbol_line_window=int(raw["matching"]["same_symbol_line_window"]),
        render_allowlist=tuple(raw["render_allowlist"]),
        link_allowlist=tuple(raw["link_allowlist"]),
        fetch_allowlist=tuple(raw["fetch_allowlist"]),
        ignore_rules=frozenset(raw.get("ignore_rules") or []),
    )


@dataclass(frozen=True)
class Family:
    name: str
    cwe: str
    patterns: tuple[str, ...]


class Families:
    """Maps (tool, rule) to a weakness family shared across tools."""

    def __init__(self, families: list[Family]) -> None:
        self.families = families
        self._cache: dict[tuple[str, str], str] = {}

    def family(self, tool: str, rule: str) -> str:
        key = (tool, rule)
        if key not in self._cache:
            ident = f"{tool}:{rule}"
            found = next((f.name for f in self.families if any(fnmatch.fnmatch(ident, p) for p in f.patterns)), "")
            self._cache[key] = found or ident
        return self._cache[key]

    def cwe(self, family: str) -> str:
        return next((f.cwe for f in self.families if f.name == family), "")


@lru_cache(maxsize=4)
def load_families(config_dir: str | None = None) -> Families:
    d = Path(config_dir) if config_dir else CONFIG_DIR
    raw = yaml.safe_load((d / "rule_families.yaml").read_text())
    return Families([Family(name, spec.get("cwe", ""), tuple(spec["rules"])) for name, spec in raw.items()])

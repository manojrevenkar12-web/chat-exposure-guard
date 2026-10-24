"""The finding model every importer and checker produces.

A *Finding* is one detection by one tool in one scan. Many findings (from several tools, several
scans, several locations) can describe the same underlying *issue*; turning findings into issues is
the job of :mod:`ceg.matching`. Findings never carry secret values, only salted hashes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Kind(StrEnum):
    CODE = "code"  # static analysis of source code
    DEPENDENCY = "dependency"  # vulnerable package version
    SECRET = "secret"  # noqa: S105 - credential in code, config or client bundle
    EXPOSURE = "exposure"  # data store or endpoint reachable without auth
    DYNAMIC = "dynamic"  # DAST (ZAP) on a running service
    PENTEST = "pentest"  # from an external audit or penetration test report
    ACCESS = "access"  # identity and device hygiene
    AI = "ai"  # LLM application security


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]

    @classmethod
    def from_rank(cls, rank: int) -> Severity:
        rank = max(0, min(4, rank))
        return [cls.INFO, cls.LOW, cls.MEDIUM, cls.HIGH, cls.CRITICAL][rank]


@dataclass(frozen=True)
class Location:
    path: str
    start_line: int = 0
    end_line: int = 0
    symbol: str = ""  # enclosing function or class, "<module>" at top level
    snippet: str = ""  # the flagged source text, as the tool reported it


@dataclass
class Finding:
    tool: str  # semgrep, bandit, codeql, osv-scanner, gitleaks, zap, pentest, ceg-exposure, ...
    rule: str  # the tool's own rule or check id
    kind: Kind
    title: str
    severity: Severity
    location: Location | None = None
    cwe: str = ""
    # dependency findings
    ecosystem: str = ""
    package: str = ""
    version: str = ""
    advisory_ids: tuple[str, ...] = ()
    fixed_version: str = ""
    # secret findings: salted SHA-256 of the value, never the value itself
    secret_hash: str = ""
    # exposure, dynamic, access, pentest findings: what is exposed
    resource: str = ""
    service: str = ""  # resolved from the risk register when empty
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def path(self) -> str:
        return self.location.path if self.location else ""

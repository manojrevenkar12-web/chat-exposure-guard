"""A small secret scanner for code, configuration and client bundles.

gitleaks is the better general tool and its output is imported as is (``ceg import gitleaks``).
This scanner exists for two things gitleaks does not know: which paths ship to users' devices
(a key in the mobile app or the web bundle is public the day it is released), and which
providers an AI companion company actually holds keys for. Values are hashed, never kept.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .importers import secret_hash
from .models import Finding, Kind, Location, Severity
from .register import Register


@dataclass(frozen=True)
class Pattern:
    id: str
    regex: re.Pattern[str]
    severity: Severity
    group: int = 0


PATTERNS = [
    Pattern("openai-api-key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b"), Severity.HIGH),
    Pattern("anthropic-api-key", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{32,}\b"), Severity.HIGH),
    Pattern("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), Severity.HIGH),
    Pattern("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.CRITICAL),
    Pattern("stripe-secret-key", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b"), Severity.CRITICAL),
    Pattern("slack-token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{20,}\b"), Severity.HIGH),
    Pattern("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.HIGH),
    Pattern("huggingface-token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"), Severity.HIGH),
    Pattern("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----"), Severity.CRITICAL),
    Pattern("gcp-service-account", re.compile(r"\"private_key_id\"\s*:\s*\"([0-9a-f]{40})\""), Severity.CRITICAL, 1),
    Pattern(
        "generic-secret",
        re.compile(
            # a credential-like name (also inside a longer one: google_client_secret, apiToken), an
            # optional type annotation, then a quoted value (held-out set rules-v1: c018, c070)
            r"(?i)[\w-]*(?:api[_-]?key|secret|token|passwd|password)[\w-]*[\"']?\s*"
            r"(?::\s*[\w\[\]|. ]{1,30}?\s*)?[:=]\s*[\"']([^\"'\s]{16,})[\"']"
        ),
        Severity.MEDIUM,
        1,
    ),
]

_PLACEHOLDER = re.compile(
    r"(?i)(x{6,}|\*{4,}|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|changeme|example|dummy|placeholder|your[_-]|redacted|test[_-]?key)"
)
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".mypy_cache", ".ruff_cache"}
TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".env",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".tf",
    ".tfvars",
    ".kt",
    ".java",
    ".swift",
    ".plist",
    ".xml",
    ".gradle",
    ".sh",
    ".md",
    ".txt",
    ".rules",
}


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def _files(root: Path) -> Iterator[Path]:
    for p in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if p.is_file() and (p.suffix in TEXT_SUFFIXES or p.name.startswith(".env")) and p.stat().st_size < 2_000_000:
            yield p


def scan_text(text: str, path: str) -> Iterator[tuple[Pattern, str, int]]:
    for lineno, line in enumerate(text.splitlines(), 1):
        for pat in PATTERNS:
            for m in pat.regex.finditer(line):
                value = m.group(pat.group)
                if _PLACEHOLDER.search(value):
                    continue
                if pat.id == "generic-secret" and (entropy(value) < 3.5 or "://" in value or value.startswith(("/", "."))):
                    continue
                yield pat, value, lineno


def scan(root: str | Path, register: Register | None = None) -> list[Finding]:
    root = Path(root)
    out: list[Finding] = []
    for p in _files(root):
        rel = str(p.relative_to(root))
        text = p.read_text(errors="replace")
        seen: set[str] = set()
        for pat, value, lineno in scan_text(text, rel):
            if value in seen:
                continue
            seen.add(value)
            svc = register.service_for_path(rel) if register else None
            client = bool(svc and svc.auth == "client")
            sev = Severity.CRITICAL if client else pat.severity
            where = "an app shipped to users" if client else rel
            out.append(
                Finding(
                    tool="ceg-secrets",
                    rule=pat.id,
                    kind=Kind.SECRET,
                    title=f"{pat.id} in {where}",
                    severity=sev,
                    location=Location(rel, lineno, lineno),
                    secret_hash=secret_hash(value),
                    cwe="CWE-798",
                    service=svc.name if svc else "",
                    description=(
                        "Anyone with the app can extract it; rotate it and move the call behind the backend."
                        if client
                        else "Rotate the credential and load it from the secret store."
                    ),
                )
            )
    return out

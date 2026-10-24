"""Running the scanners this project ships rules for, and reading their output.

Semgrep runs the companion-platform rules in ``rules/``; Bandit runs its own Python checks. Both are
invoked with argument lists (never a shell) and their JSON is parsed by :mod:`ceg.importers`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import exposure, importers
from . import secrets as secret_scan
from .models import Finding
from .register import Register
from .settings import ROOT

RULES_DIR = ROOT / "rules"


class ScannerMissing(RuntimeError):
    pass


def _tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise ScannerMissing(f"{name} is not on PATH (pip install 'chat-exposure-guard[scanners]')")
    return path


def semgrep(target: str | Path, files: list[str] | None = None, rules: str | Path = RULES_DIR) -> list[Finding]:
    """Run Semgrep with the project's rules. ``files`` limits the scan (pull-request mode)."""
    target = Path(target)
    args = [
        _tool("semgrep"),
        "scan",
        "--config",
        str(rules),
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--quiet",
        "--no-git-ignore",
        "--exclude",
        "**/rules/**",
    ]
    if files is not None:
        if not files:
            return []
        args += [str(target / f) for f in files]
    else:
        args.append(str(target))
    proc = subprocess.run(args, capture_output=True, text=True, check=False, timeout=900)  # noqa: S603
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"semgrep failed ({proc.returncode}): {proc.stderr[-2000:]}")
    doc = json.loads(proc.stdout or "{}")
    errors = [e for e in doc.get("errors", []) if e.get("level") == "error"]
    if errors:
        raise RuntimeError(f"semgrep errors: {errors[:3]}")
    return importers.semgrep_json(doc, root=str(target))


def bandit(target: str | Path, files: list[str] | None = None) -> list[Finding]:
    target = Path(target)
    args = [_tool("bandit"), "-f", "json", "-q"]
    if files is not None:
        py = [str(target / f) for f in files if f.endswith(".py")]
        if not py:
            return []
        args += py
    else:
        args += ["-r", str(target), "-x", ".venv,node_modules,tests"]
    proc = subprocess.run(args, capture_output=True, text=True, check=False, timeout=900)  # noqa: S603
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"bandit failed ({proc.returncode}): {proc.stderr[-2000:]}")
    return importers.bandit_json(json.loads(proc.stdout or "{}"), root=str(target))


@dataclass
class ScanSet:
    """The findings of every built-in scan, per tool (the lifecycle needs to know who reported what)."""

    by_tool: dict[str, list[Finding]] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)

    @property
    def all(self) -> list[Finding]:
        return [f for fs in self.by_tool.values() for f in fs]


def scan_all(
    target: str | Path,
    register: Register | None,
    files: list[str] | None = None,
    tools: tuple[str, ...] = ("semgrep", "bandit", "ceg-secrets", "ceg-exposure"),
) -> ScanSet:
    """Run the built-in scans over a checkout (or only ``files`` of it)."""
    out = ScanSet()
    for tool in tools:
        try:
            if tool == "semgrep":
                out.by_tool[tool] = semgrep(target, files)
            elif tool == "bandit":
                out.by_tool[tool] = bandit(target, files)
            elif tool == "ceg-secrets":
                fs = secret_scan.scan(target, register)
                out.by_tool[tool] = [f for f in fs if files is None or f.path in files]
            elif tool == "ceg-exposure":
                fs = exposure.check(target, register)
                out.by_tool[tool] = [f for f in fs if files is None or f.path in files]
        except ScannerMissing as e:
            out.skipped.append(str(e))
    return out

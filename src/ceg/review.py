"""The pull-request security gate.

It scans the files a pull request changes, at the base and at the head, and reports only what the
pull request introduces: matching runs through the same tracker as the issue database, so a finding
that only moved (a refactor, a renamed file, a reformatted function) is not new. The comment names
the service from the risk register and the effective severity; the gate fails on new findings at or
above a threshold.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .matching import Issue, Scan, Status, Tracker
from .models import Finding, Severity
from .register import Register
from .scanners import scan_all
from .settings import Families, Settings
from .source import SourceIndex


@dataclass
class Change:
    status: str  # A, M, D, R
    path: str
    old_path: str = ""


@dataclass
class ReviewResult:
    introduced: list[Issue] = field(default_factory=list)
    fixed: list[Issue] = field(default_factory=list)
    unchanged: int = 0
    files: int = 0
    skipped: list[str] = field(default_factory=list)

    def blocking(self, threshold: Severity) -> list[Issue]:
        return [i for i in self.introduced if i.severity.rank >= threshold.rank]


def _git(repo: Path, *args: str) -> str:
    git = shutil.which("git") or "git"
    return subprocess.run([git, "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout  # noqa: S603


def changes(repo: Path, base: str, head: str, subdir: str = "") -> list[Change]:
    out = []
    for line in _git(repo, "diff", "--name-status", "-M", f"{base}...{head}", "--", subdir or ".").splitlines():
        parts = line.split("\t")
        st = parts[0][0]
        if st == "R":
            out.append(Change("R", parts[2], parts[1]))
        else:
            out.append(Change(st, parts[1]))
    return out


def _export(repo: Path, ref: str, dest: Path, paths: list[str]) -> None:
    """Write the given paths as they are at ref into dest (git archive keeps it read-only)."""
    for p in paths:
        try:
            blob = subprocess.run(  # noqa: S603
                [shutil.which("git") or "git", "-C", str(repo), "show", f"{ref}:{p}"], capture_output=True, check=True
            ).stdout
        except subprocess.CalledProcessError:
            continue
        target = dest / p
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)


def review(
    repo: str | Path, base: str, head: str, register: Register | None, families: Families, settings: Settings, subdir: str = ""
) -> ReviewResult:
    repo = Path(repo)
    chs = changes(repo, base, head, subdir)
    prefix = (subdir.rstrip("/") + "/") if subdir else ""

    def rel(p: str) -> str:
        return p[len(prefix) :] if prefix and p.startswith(prefix) else p

    base_files = [c.old_path or c.path for c in chs if c.status != "A"]
    head_files = [c.path for c in chs if c.status != "D"]
    renames = {rel(c.old_path): rel(c.path) for c in chs if c.status == "R"}
    res = ReviewResult(files=len(chs))
    with tempfile.TemporaryDirectory() as td:
        base_dir, head_dir = Path(td, "base"), Path(td, "head")
        base_dir.mkdir()
        head_dir.mkdir()
        _export(repo, base, base_dir, base_files)
        _export(repo, head, head_dir, head_files)
        root_base = base_dir / subdir if subdir else base_dir
        root_head = head_dir / subdir if subdir else head_dir
        root_base.mkdir(parents=True, exist_ok=True)
        root_head.mkdir(parents=True, exist_ok=True)
        before = scan_all(root_base, register, files=[rel(f) for f in base_files])
        after = scan_all(root_head, register, files=[rel(f) for f in head_files])
        res.skipped = sorted(set(before.skipped + after.skipped))
        t = Tracker(register, families, settings)
        now = datetime.now(UTC)
        for tool, base_fs in before.by_tool.items():
            t.ingest(Scan(f"base:{tool}", tool, "repo", True, now, base), base_fs, SourceIndex(root_base))
        known = set(t.issues)
        if renames:
            t.apply_renames(renames, Scan("head:renames", "git", "repo", False, now, head))
        for tool in sorted(set(before.by_tool) | set(after.by_tool)):
            fs: list[Finding] = after.by_tool.get(tool, [])
            t.ingest(Scan(f"head:{tool}", tool, "repo", True, now, head), fs, SourceIndex(root_head))
    res.introduced = sorted((i for iid, i in t.issues.items() if iid not in known), key=lambda i: (-i.severity.rank, i.path))
    res.fixed = [i for iid, i in t.issues.items() if iid in known and i.status == Status.FIXED]
    res.unchanged = sum(1 for iid, i in t.issues.items() if iid in known and i.status == Status.OPEN)
    return res


def comment(res: ReviewResult, threshold: Severity) -> str:
    """Markdown for the pull request."""
    blocking = res.blocking(threshold)
    lines = ["### Security review", ""]
    if not res.introduced:
        lines.append(f"No new findings in {res.files} changed files.")
    else:
        verdict = (
            f"**{len(blocking)} new finding(s) at {threshold.value} or above block this merge.**"
            if blocking
            else "New findings below the blocking threshold; please look at them."
        )
        lines += [verdict, "", "| Severity | Where | What | Service |", "|---|---|---|---|"]
        for i in res.introduced:
            loc = sorted(i.locations)[0] if i.locations else i.resource
            where = f"`{loc}`" + (f" in `{i.symbol}`" if i.symbol and i.symbol != "<module>" else "")
            lines.append(f"| {i.severity.value} | {where} | {i.title} | {i.service or '–'} |")
        lines.append("")
        for i in res.introduced:
            if i.severity_reason and "raised" in i.severity_reason:
                lines.append(f"- {i.id.replace('CEG', 'new')}: {i.severity_reason}.")
    if res.fixed:
        lines += ["", f"Fixed by this change: {', '.join(sorted(i.title for i in res.fixed))}."]
    if res.skipped:
        lines += ["", "Not run: " + "; ".join(res.skipped)]
    lines += ["", "<sub>chat-exposure-guard · findings that only moved are not reported as new</sub>"]
    return "\n".join(lines)

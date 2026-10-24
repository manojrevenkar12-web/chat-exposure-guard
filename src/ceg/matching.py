"""Turning detections into issues, scan after scan.

The tracker keeps one issue per underlying weakness, whichever tools report it and wherever the code
around it moves. It is a pure state machine: give it a scan and its findings, it updates its issues.
:mod:`ceg.store` persists the same state in PostgreSQL.

Identity, by kind:

* code: the weakness family (Semgrep's and Bandit's SQL injection rules are one family), the file,
  the enclosing function, and either the flagged line's normalised text or its position inside the
  function. Line numbers alone are never an identity.
* dependency: ecosystem, package, scope, and any overlap in advisory ids (GHSA and CVE aliases).
* secret: the salted hash of the value, wherever it appears. One leaked key is one rotation.
* everything else: family and resource.

Lifecycle: an issue is fixed when every tool that reported it has run a full scan of its scope and
no longer reports it. A partial scan (a pull request diff) never fixes anything. A fixed issue that
comes back is reopened, not created again.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from .models import Finding, Kind, Severity
from .priority import assess, due
from .register import Register
from .settings import Families, Settings
from .source import MODULE, SourceIndex, snippet_hash


class Status(StrEnum):
    OPEN = "open"
    FIXED = "fixed"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"


@dataclass(frozen=True)
class Scan:
    id: str
    tool: str
    scope: str  # a service name, or "repo" for the whole repository
    full: bool  # a full scan of the scope can fix issues; a diff scan cannot
    at: datetime
    commit: str = ""


@dataclass
class Anchor:
    tool: str
    rule: str
    path: str
    symbol: str
    rel_line: int  # line relative to the enclosing symbol's first line
    line: int
    snippet: str  # hash of the normalised flagged line


@dataclass
class Event:
    at: datetime
    kind: str  # opened, detected, fixed, reopened, severity, suppressed, moved
    detail: str
    scan: str = ""


@dataclass
class Issue:
    id: str
    kind: Kind
    family: str
    title: str
    cwe: str
    service: str
    tool_severity: Severity
    severity: Severity
    severity_reason: str
    status: Status
    first_seen: datetime
    last_seen: datetime
    opened_at: datetime  # first seen, or last reopened
    due_at: datetime
    fixed_at: datetime | None = None
    reopen_count: int = 0
    # tool -> id of the last scan in which it reported the issue
    reporting: dict[str, str] = field(default_factory=dict)
    anchors: list[Anchor] = field(default_factory=list)
    path: str = ""
    symbol: str = ""
    ecosystem: str = ""
    package: str = ""
    advisories: set[str] = field(default_factory=set)
    secret_hash: str = ""
    resource: str = ""
    locations: set[str] = field(default_factory=set)
    events: list[Event] = field(default_factory=list)
    detections: int = 0

    @property
    def tools(self) -> list[str]:
        return sorted(self.reporting)


@dataclass
class Detection:
    """A finding with its resolved identity, before matching."""

    finding: Finding
    family: str
    service: str
    path: str
    symbol: str
    symbol_start: int
    snippet: str


class Tracker:
    def __init__(self, register: Register | None, families: Families, settings: Settings) -> None:
        self.register = register
        self.families = families
        self.settings = settings
        self.issues: dict[str, Issue] = {}
        self._seq = itertools.count(1)
        self.dirty: set[str] = set()  # issues changed since the store last saved
        self.matches: list[tuple[str, Finding, str]] = []  # (scan id, finding, issue id), for evaluation

    # -- identity --------------------------------------------------------------------------------

    def _service(self, f: Finding) -> str:
        if f.service:
            return f.service
        if self.register and f.path:
            s = self.register.service_for_path(f.path)
            if s:
                return s.name
        return ""

    def resolve(self, f: Finding, source: SourceIndex) -> Detection:
        family = self.families.family(f.tool, f.rule)
        path, sym, start, snip = f.path, "", 0, ""
        if f.kind in (Kind.CODE,) and f.location:
            line = f.location.start_line
            symbol = source.symbol(path, line) if source.root else MODULE
            if source.root is None and f.location.symbol:
                sym, start = f.location.symbol, 0
            else:
                sym, start = symbol.name, symbol.start
            text = source.line(path, line) if source.root else ""
            if not text and f.location.snippet:
                text = f.location.snippet.splitlines()[0]
            snip = snippet_hash(text)
        return Detection(f, family, self._service(f), path, sym, start, snip)

    def _rel(self, d: Detection) -> int:
        line = d.finding.location.start_line if d.finding.location else 0
        return line - d.symbol_start if d.symbol_start else line

    def _match_code(self, d: Detection, taken: set[tuple[str, str]]) -> Issue | None:
        tool = d.finding.tool
        window = self.settings.same_symbol_line_window
        cands = [i for i in self.issues.values() if i.kind == Kind.CODE and i.family == d.family and (i.id, tool) not in taken]
        if not cands:
            return None
        rel = self._rel(d)
        # 1. same normalised line, same file
        for i in cands:
            if i.path == d.path and d.snippet and any(a.snippet == d.snippet for a in i.anchors):
                return i
        # 2. same file and function, close to where it was (another tool, or the line was edited)
        best: tuple[int, Issue] | None = None
        for i in cands:
            if i.path == d.path and i.symbol == d.symbol and d.symbol not in ("", "<module>"):
                dist = min((abs(a.rel_line - rel) for a in i.anchors), default=window + 1)
                if dist <= window and (best is None or dist < best[0]):
                    best = (dist, i)
        if best:
            return best[1]
        # 3. same function name and same line, another file: the code moved
        for i in cands:
            if (
                i.path != d.path
                and d.snippet
                and i.symbol == d.symbol
                and d.symbol not in ("", "<module>")
                and any(a.snippet == d.snippet for a in i.anchors)
            ):
                return i
        # 4. same file and same line, function renamed
        for i in cands:
            if i.path == d.path and d.snippet and any(a.snippet == d.snippet for a in i.anchors):
                return i
        # 5. module-level code: same file, close by position
        if d.symbol in ("", "<module>"):
            for i in cands:
                if (
                    i.path == d.path
                    and i.symbol in ("", "<module>")
                    and min((abs(a.line - rel) for a in i.anchors), default=window + 1) <= window
                ):
                    return i
        return None

    def _match_other(self, d: Detection) -> Issue | None:
        f = d.finding
        for i in self.issues.values():
            if i.kind != f.kind:
                continue
            if f.kind == Kind.SECRET:
                if f.secret_hash and i.secret_hash == f.secret_hash:
                    return i
            elif f.kind == Kind.DEPENDENCY:
                if (
                    i.ecosystem == f.ecosystem
                    and i.package == f.package.lower()
                    and i.service == d.service
                    and i.advisories & set(f.advisory_ids)
                ):
                    return i
            elif i.family == d.family and i.resource == f.resource and i.service == d.service:
                return i
        return None

    # -- scans ------------------------------------------------------------------------------------

    def start_ids_at(self, n: int) -> None:
        self._seq = itertools.count(n)

    def ingest(
        self,
        scan: Scan,
        findings: list[Finding],
        source: SourceIndex | None = None,
        renames: dict[str, str] | None = None,
    ) -> list[Issue]:
        """Apply one scan. Returns the issues the scan touched."""
        source = source or SourceIndex(None)
        if renames:
            self.apply_renames(renames, scan)
        touched: dict[str, Issue] = {}
        taken: set[tuple[str, str]] = set()
        for f in findings:
            if f"{f.tool}:{f.rule}" in self.settings.ignore_rules:
                continue
            d = self.resolve(f, source)
            issue = self._match_code(d, taken) if f.kind == Kind.CODE else self._match_other(d)
            if issue is None:
                issue = self._open(d, scan)
            else:
                self._update(issue, d, scan)
            if f.kind == Kind.CODE:
                taken.add((issue.id, f.tool))
            touched[issue.id] = issue
            self.matches.append((scan.id, f, issue.id))
        if scan.full:
            self._resolve_missing(scan, touched)
        self.dirty |= set(touched)
        return list(touched.values())

    def apply_renames(self, renames: dict[str, str], scan: Scan) -> None:
        for i in self.issues.values():
            if i.path in renames:
                new = renames[i.path]
                i.events.append(Event(scan.at, "moved", f"{i.path} -> {new}", scan.id))
                i.path = new
                for a in i.anchors:
                    if a.path in renames:
                        a.path = renames[a.path]
                self.dirty.add(i.id)

    def _assess(self, i: Issue, quiet: bool = False) -> None:
        svc = self.register.get(i.service) if self.register and i.service else None
        a = assess(i.tool_severity, i.kind, svc, self.settings)
        if a.severity != i.severity and not quiet:
            i.events.append(Event(i.last_seen, "severity", f"{i.severity.value} -> {a.severity.value}: {a.reason}"))
        i.severity, i.severity_reason = a.severity, a.reason
        i.due_at = due(i.opened_at, i.severity, self.settings)

    def _anchor(self, d: Detection) -> Anchor:
        f = d.finding
        line = f.location.start_line if f.location else 0
        return Anchor(f.tool, f.rule, d.path, d.symbol, self._rel(d), line, d.snippet)

    def _open(self, d: Detection, scan: Scan) -> Issue:
        f = d.finding
        iid = f"CEG-{next(self._seq)}"
        i = Issue(
            id=iid,
            kind=f.kind,
            family=d.family,
            title=f.title,
            cwe=f.cwe or self.families.cwe(d.family),
            service=d.service,
            tool_severity=f.severity,
            severity=f.severity,
            severity_reason="",
            status=Status.OPEN,
            first_seen=scan.at,
            last_seen=scan.at,
            opened_at=scan.at,
            due_at=scan.at,
            path=d.path,
            symbol=d.symbol,
            ecosystem=f.ecosystem,
            package=f.package.lower(),
            advisories=set(f.advisory_ids),
            secret_hash=f.secret_hash,
            resource=f.resource,
        )
        i.reporting[f.tool] = scan.id
        i.anchors.append(self._anchor(d))
        if d.path:
            i.locations.add(f"{d.path}:{f.location.start_line if f.location else 0}")
        i.detections = 1
        self._assess(i, quiet=True)  # the opening event carries the first severity and its reason
        i.events.append(
            Event(
                scan.at,
                "opened",
                f"{f.tool}:{f.rule}, {i.severity.value}" + (f" ({i.severity_reason})" if i.severity_reason else ""),
                scan.id,
            )
        )
        self.issues[iid] = i
        return i

    def _update(self, i: Issue, d: Detection, scan: Scan) -> None:
        f = d.finding
        i.detections += 1
        i.last_seen = scan.at
        if f.tool not in i.reporting and i.status != Status.FIXED:
            i.events.append(Event(scan.at, "detected", f"also reported by {f.tool}:{f.rule}", scan.id))
        i.reporting[f.tool] = scan.id
        if f.kind == Kind.CODE:
            if d.path != i.path:
                i.events.append(Event(scan.at, "moved", f"{i.path} -> {d.path}", scan.id))
                i.path = d.path
            i.symbol = d.symbol
            # keep the latest anchor per tool
            i.anchors = [a for a in i.anchors if a.tool != f.tool] + [self._anchor(d)]
        i.advisories |= set(f.advisory_ids)
        if d.path:
            i.locations.add(f"{d.path}:{f.location.start_line if f.location else 0}")
        if f.severity.rank > i.tool_severity.rank:
            i.tool_severity = f.severity
            self._assess(i)
        if i.status == Status.FIXED:
            i.status = Status.OPEN
            i.reopen_count += 1
            i.fixed_at = None
            i.opened_at = scan.at
            i.events.append(Event(scan.at, "reopened", f"{f.tool} reports it again", scan.id))
            self._assess(i)

    def _resolve_missing(self, scan: Scan, touched: dict[str, Issue]) -> None:
        for i in self.issues.values():
            if i.id in touched or scan.tool not in i.reporting:
                continue
            if scan.scope != "repo" and i.service != scan.scope:
                continue
            del i.reporting[scan.tool]
            if not i.reporting and i.status == Status.OPEN:
                i.status = Status.FIXED
                i.fixed_at = scan.at
                i.events.append(Event(scan.at, "fixed", f"no longer reported by {scan.tool}", scan.id))
            self.dirty.add(i.id)

    # -- triage -----------------------------------------------------------------------------------

    def suppress(self, issue_id: str, status: Status, reason: str, at: datetime) -> Issue:
        if status not in (Status.RISK_ACCEPTED, Status.FALSE_POSITIVE):
            raise ValueError("suppress with risk_accepted or false_positive")
        if not reason.strip():
            raise ValueError("a suppression needs a reason")
        i = self.issues[issue_id]
        i.status = status
        i.events.append(Event(at, "suppressed", f"{status.value}: {reason}"))
        self.dirty.add(i.id)
        return i

    def unsuppress(self, issue_id: str, at: datetime, why: str) -> Issue:
        i = self.issues[issue_id]
        i.status = Status.OPEN if i.reporting else Status.FIXED
        i.events.append(Event(at, "unsuppressed", why))
        self.dirty.add(i.id)
        return i

    def open_issues(self) -> list[Issue]:
        return sorted(
            (i for i in self.issues.values() if i.status == Status.OPEN),
            key=lambda i: (-i.severity.rank, i.due_at, i.id),
        )


class LineTracker(Tracker):
    """The common default, for comparison: an issue is (tool, rule, path, line). No families, no
    functions, no cross-tool merging; the same lifecycle otherwise."""

    def _match_code(self, d: Detection, taken: set[tuple[str, str]]) -> Issue | None:
        f = d.finding
        line = f.location.start_line if f.location else 0
        for i in self.issues.values():
            if (
                i.kind == Kind.CODE
                and (i.id, f.tool) not in taken
                and i.path == d.path
                and any(a.tool == f.tool and a.rule == f.rule and a.line == line for a in i.anchors)
            ):
                return i
        return None

    def resolve(self, f: Finding, source: SourceIndex) -> Detection:
        d = super().resolve(f, source)
        d.family = f"{f.tool}:{f.rule}"
        return d

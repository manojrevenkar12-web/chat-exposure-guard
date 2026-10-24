"""PostgreSQL persistence for issues, their audit trail and scans.

Imports are serialised with a transaction-level advisory lock: two CI jobs importing at once would
otherwise both decide an issue is new. The tracker's matching runs in memory on the loaded state.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row

from .matching import Anchor, Issue, Scan, Status, Tracker
from .models import Kind, Severity
from .register import Register
from .settings import ROOT, Families, Settings

MIGRATIONS = ROOT / "migrations"
IMPORT_LOCK = 0x0CE6_1550


class Store:
    def __init__(self, dsn: str) -> None:
        self.dsn = dsn

    @contextmanager
    def conn(self) -> Iterator[psycopg.Connection[dict[str, Any]]]:
        with psycopg.connect(self.dsn, row_factory=dict_row) as c:
            yield c

    def migrate(self, directory: Path = MIGRATIONS) -> list[str]:
        applied = []
        with self.conn() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
            )
            done = {r["name"] for r in c.execute("SELECT name FROM schema_migrations")}
            for f in sorted(directory.glob("*.sql")):
                if f.name in done:
                    continue
                c.execute(f.read_text())  # type: ignore[arg-type]
                c.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (f.name,))
                applied.append(f.name)
        return applied

    # -- loading ----------------------------------------------------------------------------------

    def load(
        self, c: psycopg.Connection[dict[str, Any]], register: Register | None, families: Families, settings: Settings
    ) -> Tracker:
        t = Tracker(register, families, settings)
        top = 0
        for r in c.execute("SELECT * FROM issues"):
            i = _issue(r)
            t.issues[i.id] = i
            top = max(top, r["seq"])
        t.start_ids_at(top + 1)
        return t

    def save(self, c: psycopg.Connection[dict[str, Any]], t: Tracker, actor: str = "system") -> int:
        n = 0
        for iid in sorted(t.dirty):
            i = t.issues[iid]
            row = _row(i)
            cols = list(row)
            c.execute(
                f"INSERT INTO issues ({', '.join(cols)}) VALUES ({', '.join('%(' + k + ')s' for k in cols)}) "  # noqa: S608
                f"ON CONFLICT (id) DO UPDATE SET {', '.join(f'{k} = EXCLUDED.{k}' for k in cols if k not in ('id', 'seq'))}, "
                "updated_at = now()",
                row,
            )
            for e in i.events:
                c.execute(
                    "INSERT INTO issue_events (issue_id, at, kind, detail, scan_id, actor) VALUES (%s, %s, %s, %s, %s, %s)",
                    (i.id, e.at, e.kind, e.detail, e.scan, actor),
                )
            i.events.clear()
            n += 1
        t.dirty.clear()
        return n

    # -- operations -------------------------------------------------------------------------------

    def ingest(
        self,
        scan: Scan,
        findings: list[Any],
        register: Register | None,
        families: Families,
        settings: Settings,
        source: Any = None,
        renames: dict[str, str] | None = None,
    ) -> dict[str, int]:
        with self.conn() as c, c.transaction():
            c.execute("SELECT pg_advisory_xact_lock(%s)", (IMPORT_LOCK,))
            if c.execute("SELECT 1 FROM scans WHERE id = %s", (scan.id,)).fetchone():
                return {"duplicate_scan": 1}
            t = self.load(c, register, families, settings)
            before = {iid: (i.status, i.reopen_count) for iid, i in t.issues.items()}
            t.ingest(scan, findings, source, renames)
            stats = {"findings": len(findings), "opened": 0, "fixed": 0, "reopened": 0}
            for iid in t.dirty:
                i = t.issues[iid]
                if iid not in before:
                    stats["opened"] += 1
                elif i.status == Status.FIXED and before[iid][0] != Status.FIXED:
                    stats["fixed"] += 1
                elif i.reopen_count > before[iid][1]:
                    stats["reopened"] += 1
            self.save(c, t)
            c.execute(
                "INSERT INTO scans (id, tool, scope, full_scan, commit_sha, at, findings, opened, fixed, reopened) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    scan.id,
                    scan.tool,
                    scan.scope,
                    scan.full,
                    scan.commit,
                    scan.at,
                    len(findings),
                    stats["opened"],
                    stats["fixed"],
                    stats["reopened"],
                ),
            )
            return stats

    def suppress(
        self,
        issue_id: str,
        status: Status,
        reason: str,
        actor: str,
        until: datetime | None,
        register: Register | None,
        families: Families,
        settings: Settings,
        now: datetime,
    ) -> Issue:
        if status == Status.RISK_ACCEPTED:
            if until is None:
                raise ValueError("a risk acceptance needs an expiry date")
            if (until - now).days > settings.max_risk_acceptance_days:
                raise ValueError(f"risk acceptances last at most {settings.max_risk_acceptance_days} days")
        with self.conn() as c, c.transaction():
            c.execute("SELECT pg_advisory_xact_lock(%s)", (IMPORT_LOCK,))
            t = self.load(c, register, families, settings)
            if issue_id not in t.issues:
                raise KeyError(issue_id)
            i = t.suppress(issue_id, status, f"{reason} (by {actor}" + (f", until {until.date()})" if until else ")"), now)
            self.save(c, t, actor=actor)
            c.execute("UPDATE issues SET accepted_until = %s WHERE id = %s", (until, issue_id))
            return i

    def expire_acceptances(self, now: datetime, register: Register | None, families: Families, settings: Settings) -> list[str]:
        """Risk acceptances end on their date; the issue comes back as open (or fixed)."""
        with self.conn() as c, c.transaction():
            c.execute("SELECT pg_advisory_xact_lock(%s)", (IMPORT_LOCK,))
            ids = [
                r["id"]
                for r in c.execute(
                    "SELECT id FROM issues WHERE status = 'risk_accepted' "
                    "AND accepted_until IS NOT NULL AND accepted_until <= %s",
                    (now,),
                )
            ]
            if not ids:
                return []
            t = self.load(c, register, families, settings)
            for iid in ids:
                t.unsuppress(iid, now, "risk acceptance expired")
            self.save(c, t)
            c.execute("UPDATE issues SET accepted_until = NULL WHERE id = ANY(%s)", (ids,))
            return ids

    def issues(
        self,
        status: str | None = None,
        service: str | None = None,
        severity: str | None = None,
        kind: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        where, args = [], []
        for col, val in (("status", status), ("service", service), ("severity", severity), ("kind", kind)):
            if val:
                where.append(f"{col} = %s")
                args.append(val)
        # column names come from the fixed tuple above; values are parameters
        sql = "SELECT * FROM issues" + (" WHERE " + " AND ".join(where) if where else "")  # noqa: S608
        sql += (
            " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 3 ELSE 4 END, due_at, seq LIMIT %s OFFSET %s"
        )
        with self.conn() as c:
            return [_public(r) for r in c.execute(sql, [*args, limit, offset])]  # type: ignore[arg-type]

    def issue(self, issue_id: str) -> dict[str, Any] | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM issues WHERE id = %s", (issue_id,)).fetchone()
            if not r:
                return None
            out = _public(r)
            out["events"] = [
                {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in e.items() if k != "issue_id"}
                for e in c.execute(
                    "SELECT at, kind, detail, scan_id, actor FROM issue_events WHERE issue_id = %s ORDER BY id", (issue_id,)
                )
            ]
            return out

    def tracker(self, register: Register | None, families: Families, settings: Settings) -> Tracker:
        with self.conn() as c:
            return self.load(c, register, families, settings)


def _row(i: Issue) -> dict[str, Any]:
    return {
        "id": i.id,
        "seq": int(i.id.split("-")[-1]),
        "kind": i.kind.value,
        "family": i.family,
        "title": i.title,
        "cwe": i.cwe,
        "service": i.service,
        "tool_severity": i.tool_severity.value,
        "severity": i.severity.value,
        "severity_reason": i.severity_reason,
        "status": i.status.value,
        "first_seen": i.first_seen,
        "last_seen": i.last_seen,
        "opened_at": i.opened_at,
        "due_at": i.due_at,
        "fixed_at": i.fixed_at,
        "reopen_count": i.reopen_count,
        "reporting": json.dumps(i.reporting),
        "anchors": json.dumps([asdict(a) for a in i.anchors]),
        "path": i.path,
        "symbol": i.symbol,
        "ecosystem": i.ecosystem,
        "package": i.package,
        "advisories": sorted(i.advisories),
        "secret_hash": i.secret_hash,
        "resource": i.resource,
        "locations": sorted(i.locations)[:200],
        "detections": i.detections,
    }


def _issue(r: dict[str, Any]) -> Issue:
    return Issue(
        id=r["id"],
        kind=Kind(r["kind"]),
        family=r["family"],
        title=r["title"],
        cwe=r["cwe"],
        service=r["service"],
        tool_severity=Severity(r["tool_severity"]),
        severity=Severity(r["severity"]),
        severity_reason=r["severity_reason"],
        status=Status(r["status"]),
        first_seen=r["first_seen"],
        last_seen=r["last_seen"],
        opened_at=r["opened_at"],
        due_at=r["due_at"],
        fixed_at=r["fixed_at"],
        reopen_count=r["reopen_count"],
        reporting=dict(r["reporting"]),
        anchors=[Anchor(**a) for a in r["anchors"]],
        path=r["path"],
        symbol=r["symbol"],
        ecosystem=r["ecosystem"],
        package=r["package"],
        advisories=set(r["advisories"]),
        secret_hash=r["secret_hash"],
        resource=r["resource"],
        locations=set(r["locations"]),
        detections=r["detections"],
    )


def _public(r: dict[str, Any]) -> dict[str, Any]:
    out = {
        k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in r.items() if k not in ("anchors", "secret_hash", "seq")
    }
    out["tools"] = sorted(r["reporting"])
    return out

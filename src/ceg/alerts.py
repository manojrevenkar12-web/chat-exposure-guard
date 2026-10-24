"""Security alert intake and paging, including weekends.

Alerts arrive as signed webhooks (GitHub secret scanning, Dependabot, code scanning, or any source
that posts the generic format). Each is verified, normalised, deduplicated against open alerts and,
if its severity pages, sent to the on-call person. An alert nobody acknowledges climbs the
escalation chain on a timer, so a Saturday-night leaked key reaches a human even when the first
person paged is asleep.

The paging state lives in PostgreSQL. ``tick()`` runs every minute (CronJob or ``ceg alerts tick``).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

import httpx
import yaml

from .settings import CONFIG_DIR


@dataclass(frozen=True)
class Alert:
    source: str
    dedup_key: str
    severity: str
    title: str
    payload: dict[str, Any]


class SignatureError(ValueError):
    pass


def verify(secret: str, body: bytes, signature: str) -> None:
    """GitHub-style ``sha256=<hex>`` HMAC over the raw body, compared in constant time."""
    if not secret:
        raise SignatureError("no webhook secret configured for this source")
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature or ""):
        raise SignatureError("signature mismatch")


def normalise(source: str, event: str, doc: dict[str, Any]) -> Alert | None:
    """Turn a webhook into an alert, or None for events that need no one's attention."""
    if source == "github":
        repo = (doc.get("repository") or {}).get("full_name", "?")
        a = doc.get("alert") or {}
        action = doc.get("action", "")
        if event == "secret_scanning_alert" and action in ("created", "reopened"):
            kind = a.get("secret_type_display_name") or a.get("secret_type", "secret")
            sev = "critical" if a.get("validity") in ("active", None) else "high"
            return Alert(
                "github",
                f"github:secret:{repo}:{a.get('number')}",
                sev,
                f"{kind} committed to {repo} (validity: {a.get('validity', 'unknown')})",
                _trim(doc),
            )
        if event == "dependabot_alert" and action in ("created", "reopened"):
            adv = a.get("security_advisory") or {}
            sev = (adv.get("severity") or "medium").lower()
            pkg = ((a.get("dependency") or {}).get("package") or {}).get("name", "?")
            return Alert(
                "github",
                f"github:dep:{repo}:{adv.get('ghsa_id')}:{pkg}",
                sev,
                f"{pkg}: {adv.get('summary', adv.get('ghsa_id', 'advisory'))} in {repo}",
                _trim(doc),
            )
        if event == "code_scanning_alert" and action in ("created", "reopened", "appeared_in_branch"):
            rule = a.get("rule") or {}
            sev = (rule.get("security_severity_level") or rule.get("severity") or "medium").lower()
            sev = {"error": "high", "warning": "medium", "note": "low"}.get(sev, sev)
            return Alert(
                "github",
                f"github:code:{repo}:{a.get('number')}",
                sev,
                f"{rule.get('description') or rule.get('id', 'code scanning alert')} in {repo}",
                _trim(doc),
            )
        return None
    # generic: {"key": ..., "severity": ..., "title": ...}
    if not doc.get("title"):
        raise ValueError("generic alerts need a title")
    sev = str(doc.get("severity", "medium")).lower()
    if sev not in ("critical", "high", "medium", "low"):
        raise ValueError(f"unknown severity {sev!r}")
    key = str(doc.get("key") or hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()[:16])
    return Alert(source, f"{source}:{key}", sev, str(doc["title"])[:300], _trim(doc))


def _trim(doc: dict[str, Any]) -> dict[str, Any]:
    """Keep what a responder needs; never store a secret value a payload might carry."""
    d = json.loads(json.dumps(doc))
    a = d.get("alert") or {}
    for k in ("secret", "secret_value"):
        a.pop(k, None)
        d.pop(k, None)
    return d


@dataclass(frozen=True)
class OnCall:
    rotation_start: datetime
    rotation: list[dict[str, str]]
    lead: str
    contacts: dict[str, dict[str, str]]
    policy: dict[str, dict[str, Any]]
    dedup_window: timedelta

    @classmethod
    def load(cls, path: str | Path | None = None) -> OnCall:
        raw = yaml.safe_load(Path(path or CONFIG_DIR / "oncall.yaml").read_text())
        return cls(
            datetime.fromisoformat(raw["rotation_start"]),
            raw["rotation"],
            raw["lead"],
            raw["contacts"],
            raw["policy"],
            timedelta(hours=raw.get("dedup_window_hours", 24)),
        )

    def on_duty(self, at: datetime) -> dict[str, str]:
        weeks = int((at - self.rotation_start).total_seconds() // (7 * 24 * 3600))
        return self.rotation[weeks % len(self.rotation)]

    def target(self, level_name: str, at: datetime) -> str:
        return self.lead if level_name == "lead" else self.on_duty(at)[level_name]

    def plan(self, severity: str) -> tuple[list[str], list[int]]:
        p = self.policy.get(severity, {"page": False})
        if not p.get("page"):
            return [], []
        return list(p["levels"]), [int(m) for m in p["ack_minutes"]]


class Notifier(Protocol):
    def page(self, target: str, contact: dict[str, str], alert_id: int, title: str, severity: str, level: int) -> str: ...


class SlackNotifier:
    def __init__(self, webhook_url: str, timeout: float = 10.0) -> None:
        self.url = webhook_url
        self.timeout = timeout

    def page(self, target: str, contact: dict[str, str], alert_id: int, title: str, severity: str, level: int) -> str:
        text = f"{contact.get('slack', target)} [{severity.upper()}] security alert #{alert_id}: {title}"
        if level > 0:
            text += f" (escalated, level {level + 1}: the previous person did not acknowledge)"
        httpx.post(self.url, json={"text": text}, timeout=self.timeout).raise_for_status()
        return "slack"


class RecordingNotifier:
    """For tests and drills."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, int, str, int]] = []

    def page(self, target: str, contact: dict[str, str], alert_id: int, title: str, severity: str, level: int) -> str:
        self.sent.append((target, alert_id, severity, level))
        return "recorded"


class AlertDesk:
    """Alert state in PostgreSQL."""

    def __init__(self, store: Any, oncall: OnCall, notifier: Notifier) -> None:
        self.store = store
        self.oncall = oncall
        self.notifier = notifier

    def receive(self, alert: Alert, now: datetime) -> dict[str, Any]:
        with self.store.conn() as c, c.transaction():
            row = c.execute(
                "SELECT * FROM alerts WHERE dedup_key = %s AND status <> 'resolved' FOR UPDATE", (alert.dedup_key,)
            ).fetchone()
            if row and now - row["last_received_at"] <= self.oncall.dedup_window:
                c.execute(
                    "UPDATE alerts SET occurrences = occurrences + 1, last_received_at = %s WHERE id = %s", (now, row["id"])
                )
                return {"id": row["id"], "deduplicated": True}
            if row:  # an old open alert came back after the window: close the old one, start again
                c.execute("UPDATE alerts SET status = 'resolved' WHERE id = %s", (row["id"],))
            levels, waits = self.oncall.plan(alert.severity)
            nxt = now + timedelta(minutes=waits[0]) if levels and len(levels) > 1 else None
            r = c.execute(
                "INSERT INTO alerts (source, dedup_key, severity, title, payload, status, received_at, last_received_at, "
                "level, next_escalation_at) VALUES (%s, %s, %s, %s, %s, 'open', %s, %s, 0, %s) RETURNING id",
                (alert.source, alert.dedup_key, alert.severity, alert.title, json.dumps(alert.payload), now, now, nxt),
            ).fetchone()
            aid = r["id"]
            if levels:
                self._page(c, aid, alert.title, alert.severity, 0, levels[0], now)
            return {"id": aid, "deduplicated": False, "paged": bool(levels)}

    def _page(self, c: Any, aid: int, title: str, severity: str, level: int, level_name: str, now: datetime) -> None:
        target = self.oncall.target(level_name, now)
        channel = self.notifier.page(target, self.oncall.contacts.get(target, {}), aid, title, severity, level)
        c.execute(
            "INSERT INTO pages (alert_id, level, target, channel, sent_at) VALUES (%s, %s, %s, %s, %s)",
            (aid, level, target, channel, now),
        )

    def ack(self, alert_id: int, who: str, now: datetime) -> bool:
        with self.store.conn() as c:
            r = c.execute(
                "UPDATE alerts SET status = 'acked', acked_by = %s, acked_at = %s, next_escalation_at = NULL "
                "WHERE id = %s AND status = 'open' RETURNING id",
                (who, now, alert_id),
            ).fetchone()
            return r is not None

    def resolve(self, alert_id: int, now: datetime) -> bool:
        with self.store.conn() as c:
            r = c.execute(
                "UPDATE alerts SET status = 'resolved', next_escalation_at = NULL WHERE id = %s AND status <> 'resolved' "
                "RETURNING id",
                (alert_id,),
            ).fetchone()
            return r is not None

    def tick(self, now: datetime) -> list[int]:
        """Escalate every unacknowledged alert whose wait is over. Safe to run from two places."""
        escalated = []
        with self.store.conn() as c, c.transaction():
            due = c.execute(
                "SELECT * FROM alerts WHERE status = 'open' AND next_escalation_at <= %s ORDER BY id FOR UPDATE SKIP LOCKED",
                (now,),
            ).fetchall()
            for a in due:
                levels, waits = self.oncall.plan(a["severity"])
                level = a["level"] + 1
                if level >= len(levels):
                    c.execute("UPDATE alerts SET next_escalation_at = NULL WHERE id = %s", (a["id"],))
                    continue
                self._page(c, a["id"], a["title"], a["severity"], level, levels[level], now)
                nxt = now + timedelta(minutes=waits[level]) if level + 1 < len(levels) else None
                c.execute("UPDATE alerts SET level = %s, next_escalation_at = %s WHERE id = %s", (level, nxt, a["id"]))
                escalated.append(a["id"])
        return escalated

    def open_alerts(self) -> list[dict[str, Any]]:
        with self.store.conn() as c:
            return [
                {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in r.items() if k != "payload"}
                for r in c.execute("SELECT * FROM alerts WHERE status <> 'resolved' ORDER BY id")
            ]

"""HTTP API: issues and triage, scan imports from CI, the risk register, the weekly update, and
signed alert webhooks.

Auth: ``Authorization: Bearer <key>`` with keys from ``CEG_API_KEYS`` (``key:role`` pairs; roles
reader < triager < admin). Webhooks are authenticated by their HMAC signature instead
(``CEG_WEBHOOK_SECRET_<SOURCE>``).
"""

from __future__ import annotations

import hmac
import json
import os
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from . import importers
from .alerts import AlertDesk, SignatureError, normalise, verify
from .matching import Scan, Status
from .register import Register
from .report import register_view, weekly
from .settings import Families, Settings
from .store import Store

ROLES = {"reader": 0, "triager": 1, "admin": 2}


def _keys() -> dict[str, str]:
    out = {}
    for pair in os.environ.get("CEG_API_KEYS", "").split(","):
        if ":" in pair:
            k, role = pair.rsplit(":", 1)
            if role in ROLES and len(k) >= 16:
                out[k] = role
    return out


def require(role: str) -> Any:
    def dep(authorization: str = Header(default="")) -> str:
        token = authorization.removeprefix("Bearer ").strip()
        for key, r in _keys().items():
            if hmac.compare_digest(key, token):
                if ROLES[r] < ROLES[role]:
                    raise HTTPException(403, f"needs the {role} role")
                return r
        raise HTTPException(401, "missing or unknown API key")

    return dep


class SuppressBody(BaseModel):
    status: str = Field(pattern="^(risk_accepted|false_positive)$")
    reason: str = Field(min_length=10, max_length=2000)
    actor: str = Field(min_length=2, max_length=100)
    until: datetime | None = None


class ScanBody(BaseModel):
    format: str
    scope: str = "repo"
    full: bool = True
    commit: str = ""
    tool: str | None = None
    report: Any


class AckBody(BaseModel):
    who: str = Field(min_length=2, max_length=100)


def create_app(
    store: Store, register: Register, families: Families, settings: Settings, desk: AlertDesk | None = None, clock: Any = None
) -> FastAPI:
    now = clock or (lambda: datetime.now(UTC))
    app = FastAPI(title="chat-exposure-guard", version="0.1.0")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> dict[str, str]:
        try:
            with store.conn() as c:
                c.execute("SELECT 1")
        except Exception as e:
            raise HTTPException(503, "database unavailable") from e
        return {"status": "ready"}

    @app.get("/v1/issues", dependencies=[Depends(require("reader"))])
    def list_issues(
        status: str | None = "open",
        service: str | None = None,
        severity: str | None = None,
        kind: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return store.issues(status or None, service, severity, kind, min(limit, 500), max(offset, 0))

    @app.get("/v1/issues/{issue_id}", dependencies=[Depends(require("reader"))])
    def get_issue(issue_id: str) -> dict[str, Any]:
        i = store.issue(issue_id)
        if i is None:
            raise HTTPException(404, "no such issue")
        return i

    @app.post("/v1/issues/{issue_id}/suppress", dependencies=[Depends(require("triager"))])
    def suppress(issue_id: str, body: SuppressBody) -> dict[str, Any]:
        try:
            store.suppress(
                issue_id, Status(body.status), body.reason, body.actor, body.until, register, families, settings, now()
            )
        except KeyError as e:
            raise HTTPException(404, "no such issue") from e
        except ValueError as e:
            raise HTTPException(422, str(e)) from e
        return store.issue(issue_id) or {}

    @app.post("/v1/scans", dependencies=[Depends(require("admin"))])
    def import_scan(body: ScanBody) -> dict[str, Any]:
        if body.format not in importers.FORMATS:
            raise HTTPException(422, f"format must be one of {sorted(importers.FORMATS)}")
        try:
            extra = {"register": register} if body.format == "provider-advisories" else {}
            findings = importers.FORMATS[body.format](body.report, **extra)
        except (KeyError, TypeError, ValueError) as e:
            raise HTTPException(422, f"could not read the {body.format} report: {e}") from e
        tool = body.tool or (findings[0].tool if findings else body.format)
        scan = Scan(f"{tool}:{body.scope}:{body.commit or uuid.uuid4().hex}", tool, body.scope, body.full, now(), body.commit)
        return store.ingest(scan, findings, register, families, settings)

    @app.get("/v1/register", dependencies=[Depends(require("reader"))])
    def risk_register() -> list[dict[str, Any]]:
        return register_view(register, list(store.tracker(register, families, settings).issues.values()), now())

    @app.get("/v1/reports/weekly", response_class=PlainTextResponse, dependencies=[Depends(require("reader"))])
    def weekly_report() -> str:
        return weekly(register, list(store.tracker(register, families, settings).issues.values()), now())

    @app.post("/v1/alerts/{source}")
    async def alert_webhook(
        source: str, request: Request, x_hub_signature_256: str = Header(default=""), x_github_event: str = Header(default="")
    ) -> dict[str, Any]:
        if desk is None:
            raise HTTPException(503, "alerting is not configured")
        if not source.isalnum():
            raise HTTPException(404, "unknown source")
        body = await request.body()
        try:
            verify(os.environ.get(f"CEG_WEBHOOK_SECRET_{source.upper()}", ""), body, x_hub_signature_256)
        except SignatureError as e:
            raise HTTPException(401, str(e)) from e
        try:
            alert = normalise(source, x_github_event, json.loads(body or b"{}"))
        except (ValueError, json.JSONDecodeError) as e:
            raise HTTPException(422, str(e)) from e
        if alert is None:
            return {"ignored": True}
        return desk.receive(alert, now())

    @app.post("/v1/alerts/{alert_id}/ack", dependencies=[Depends(require("triager"))])
    def ack(alert_id: int, body: AckBody) -> dict[str, bool]:
        if desk is None:
            raise HTTPException(503, "alerting is not configured")
        return {"acked": desk.ack(alert_id, body.who, now())}

    @app.post("/v1/alerts-tick", dependencies=[Depends(require("admin"))])
    def tick() -> dict[str, Any]:
        if desk is None:
            raise HTTPException(503, "alerting is not configured")
        return {"escalated": desk.tick(now())}

    @app.get("/v1/alerts", dependencies=[Depends(require("reader"))])
    def alerts() -> list[dict[str, Any]]:
        if desk is None:
            raise HTTPException(503, "alerting is not configured")
        return desk.open_alerts()

    return app


def app_from_env() -> FastAPI:  # pragma: no cover - wiring
    from .alerts import OnCall, RecordingNotifier, SlackNotifier
    from .register import load
    from .settings import load_families, load_settings

    store = Store(os.environ["CEG_DATABASE_URL"])
    slack = os.environ.get("CEG_SLACK_WEBHOOK_URL")
    desk = AlertDesk(store, OnCall.load(), SlackNotifier(slack) if slack else RecordingNotifier())
    return create_app(store, load(os.environ["CEG_REGISTER"]), load_families(), load_settings(), desk)

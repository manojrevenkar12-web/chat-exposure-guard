import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from ceg.alerts import AlertDesk, OnCall, RecordingNotifier
from ceg.api import create_app

from .conftest import T0

pytestmark = pytest.mark.db

ADMIN, TRIAGER, READER = "a" * 24, "t" * 24, "r" * 24
H = {k: {"Authorization": f"Bearer {v}"} for k, v in (("admin", ADMIN), ("triager", TRIAGER), ("reader", READER))}

SEMGREP = {
    "results": [
        {
            "check_id": "ceg.sql-built-from-input",
            "path": "services/chat-api/app/main.py",
            "start": {"line": 40},
            "end": {"line": 40},
            "extra": {"message": "SQL built from input.", "severity": "ERROR", "metadata": {"cwe": ["CWE-89"]}},
        }
    ]
}


@pytest.fixture
def client(store, reg, families, settings, monkeypatch):
    monkeypatch.setenv("CEG_API_KEYS", f"{ADMIN}:admin,{TRIAGER}:triager,{READER}:reader,short:admin")
    monkeypatch.setenv("CEG_WEBHOOK_SECRET_GITHUB", "hook-secret")
    desk = AlertDesk(store, OnCall.load(), RecordingNotifier())
    return TestClient(create_app(store, reg, families, settings, desk, clock=lambda: T0))


def test_roles(client):
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").json() == {"status": "ready"}
    assert client.get("/v1/issues").status_code == 401
    assert client.get("/v1/issues", headers={"Authorization": "Bearer short"}).status_code == 401  # too short to be a key
    assert client.get("/v1/issues", headers=H["reader"]).json() == []
    body = {"format": "semgrep", "commit": "abc", "report": SEMGREP}
    assert client.post("/v1/scans", json=body, headers=H["triager"]).status_code == 403
    assert client.post("/v1/scans", json=body, headers=H["admin"]).json()["opened"] == 1


def test_triage_flow(client):
    client.post("/v1/scans", json={"format": "semgrep", "commit": "abc", "report": SEMGREP}, headers=H["admin"])
    [i] = client.get("/v1/issues", headers=H["reader"]).json()
    assert i["due_at"].startswith("2026-10-07")  # critical: two days
    bad = client.post(
        f"/v1/issues/{i['id']}/suppress",
        headers=H["triager"],
        json={"status": "risk_accepted", "reason": "WAF rule covers it", "actor": "ana"},
    )
    assert bad.status_code == 422
    ok = client.post(
        f"/v1/issues/{i['id']}/suppress",
        headers=H["triager"],
        json={"status": "risk_accepted", "reason": "WAF rule covers it", "actor": "ana", "until": "2026-11-01T00:00:00Z"},
    )
    assert ok.json()["status"] == "risk_accepted"
    assert (
        client.post(
            "/v1/issues/CEG-77/suppress",
            headers=H["triager"],
            json={"status": "false_positive", "reason": "not reachable code", "actor": "ana"},
        ).status_code
        == 404
    )
    assert client.post("/v1/scans", json={"format": "nope", "report": {}}, headers=H["admin"]).status_code == 422
    assert (
        client.post("/v1/scans", json={"format": "semgrep", "report": {"results": [{}]}}, headers=H["admin"]).status_code == 422
    )
    assert "chat-api" in client.get("/v1/reports/weekly", headers=H["reader"]).text
    assert client.get("/v1/register", headers=H["reader"]).json()[0]["service"]


def test_webhooks(client):
    payload = json.dumps(
        {
            "action": "created",
            "repository": {"full_name": "companion/web"},
            "alert": {"number": 3, "secret_type_display_name": "Stripe key", "validity": "active"},
        }
    ).encode()
    sig = "sha256=" + hmac.new(b"hook-secret", payload, hashlib.sha256).hexdigest()
    hdr = {"X-GitHub-Event": "secret_scanning_alert", "Content-Type": "application/json"}
    assert (
        client.post("/v1/alerts/github", content=payload, headers={**hdr, "X-Hub-Signature-256": "sha256=00"}).status_code == 401
    )
    assert client.post("/v1/alerts/slack", content=payload, headers={**hdr, "X-Hub-Signature-256": sig}).status_code == 401
    r = client.post("/v1/alerts/github", content=payload, headers={**hdr, "X-Hub-Signature-256": sig}).json()
    assert r["paged"]
    assert client.post(f"/v1/alerts/{r['id']}/ack", json={"who": "ana"}, headers=H["triager"]).json() == {"acked": True}
    assert client.get("/v1/alerts", headers=H["reader"]).json()[0]["status"] == "acked"

"""Alert intake, deduplication and escalation."""

import hashlib
import hmac
from datetime import datetime, timedelta

import pytest

from ceg.alerts import AlertDesk, OnCall, RecordingNotifier, SignatureError, normalise, verify

pytestmark = pytest.mark.db

# Saturday 3 October 2026, 02:10 Berlin: the third week of a three-person rotation, so jonas is primary.
SAT = datetime.fromisoformat("2026-10-03T02:10:00+02:00")


def secret_alert(number=7, validity="active"):
    return normalise(
        "github",
        "secret_scanning_alert",
        {
            "action": "created",
            "repository": {"full_name": "companion/mobile"},
            "alert": {
                "number": number,
                "secret_type_display_name": "OpenAI API Key",
                "validity": validity,
                "secret": "sk-should-vanish",
            },
        },
    )


def test_signatures():
    body = b'{"a": 1}'
    good = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    verify("s3cret", body, good)
    for secret, sig in (("s3cret", "sha256=00"), ("", good), ("other", good)):
        with pytest.raises(SignatureError):
            verify(secret, body, sig)


def test_normalise():
    a = secret_alert()
    assert a.severity == "critical" and "sk-should-vanish" not in str(a.payload)
    assert secret_alert(validity="inactive").severity == "high"
    assert normalise("github", "secret_scanning_alert", {"action": "resolved", "alert": {}}) is None
    dep = normalise(
        "github",
        "dependabot_alert",
        {
            "action": "created",
            "repository": {"full_name": "c/api"},
            "alert": {
                "security_advisory": {"ghsa_id": "GHSA-test-0001", "severity": "HIGH", "summary": "path traversal"},
                "dependency": {"package": {"name": "jinja2"}},
            },
        },
    )
    assert dep.severity == "high" and dep.dedup_key == "github:dep:c/api:GHSA-test-0001:jinja2"
    with pytest.raises(ValueError):
        normalise("waf", "", {"severity": "urgent", "title": "x"})


def test_rotation():
    oc = OnCall.load()
    assert oc.on_duty(SAT)["primary"] == "jonas"
    assert oc.target("lead", SAT) == "security-lead"
    assert oc.plan("medium") == ([], [])


def test_weekend_critical_escalates_until_acknowledged(store):
    rec = RecordingNotifier()
    desk = AlertDesk(store, OnCall.load(), rec)
    r = desk.receive(secret_alert(), SAT)
    assert r["paged"] and rec.sent == [("jonas", r["id"], "critical", 0)]
    assert desk.receive(secret_alert(), SAT + timedelta(minutes=3))["deduplicated"]  # GitHub retried the webhook
    assert desk.tick(SAT + timedelta(minutes=14)) == []
    assert desk.tick(SAT + timedelta(minutes=15)) == [r["id"]]
    assert desk.tick(SAT + timedelta(minutes=16)) == []  # never twice for one level
    assert desk.tick(SAT + timedelta(minutes=30)) == [r["id"]]
    assert [s[0] for s in rec.sent] == ["jonas", "manoj", "security-lead"]
    assert desk.tick(SAT + timedelta(hours=5)) == []  # nobody above the lead
    assert desk.ack(r["id"], "security-lead", SAT + timedelta(hours=5))
    assert not desk.ack(r["id"], "security-lead", SAT + timedelta(hours=5))
    with store.conn() as c:
        assert c.execute("SELECT count(*) AS n FROM pages").fetchone()["n"] == 3


def test_ack_stops_escalation_and_medium_never_pages(store):
    rec = RecordingNotifier()
    desk = AlertDesk(store, OnCall.load(), rec)
    r = desk.receive(secret_alert(8), SAT)
    desk.ack(r["id"], "jonas", SAT + timedelta(minutes=5))
    assert desk.tick(SAT + timedelta(hours=2)) == []
    m = desk.receive(normalise("waf", "", {"key": "rule-9", "severity": "medium", "title": "rate limit tripped"}), SAT)
    assert not m["paged"] and len(rec.sent) == 1


def test_repeat_after_window_is_a_new_alert(store):
    desk = AlertDesk(store, OnCall.load(), RecordingNotifier())
    a = desk.receive(secret_alert(9), SAT)
    b = desk.receive(secret_alert(9), SAT + timedelta(hours=25))
    assert not b["deduplicated"] and b["id"] != a["id"]
    assert [x["id"] for x in desk.open_alerts()] == [b["id"]]

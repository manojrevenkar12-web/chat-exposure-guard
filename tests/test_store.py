"""The tracker persisted in PostgreSQL."""

from datetime import timedelta

import pytest

from ceg.matching import Scan, Status

from .conftest import T0
from .helpers import code

pytestmark = pytest.mark.db

PATH = "services/chat-api/app/main.py"


def scan(sid, tool="semgrep", minutes=0, full=True):
    return Scan(sid, tool, "repo", full, T0 + timedelta(minutes=minutes))


def sqli(tool="semgrep", line=40):
    return code(tool, "ceg.sql-built-from-input" if tool == "semgrep" else "B608", PATH, line, "cur.execute(f'...{term}')")


def test_issues_survive_reloads_and_reopen(store, reg, families, settings):
    assert store.ingest(scan("s1"), [sqli()], reg, families, settings)["opened"] == 1
    assert store.ingest(scan("b1", "bandit", 1), [sqli("bandit")], reg, families, settings)["opened"] == 0
    [i] = store.issues()
    assert i["id"] == "CEG-1" and sorted(i["tools"]) == ["bandit", "semgrep"] and i["service"] == "chat-api"
    assert i["severity"] == "critical"  # an internet-facing service holding chat content
    store.ingest(scan("s2", minutes=10), [], reg, families, settings)
    assert store.issues()[0]["status"] == "open"  # bandit still reports it
    stats = store.ingest(scan("b2", "bandit", 11), [], reg, families, settings)
    assert stats["fixed"] == 1 and store.issues(status="fixed")[0]["id"] == "CEG-1"
    stats = store.ingest(scan("s3", minutes=20), [sqli()], reg, families, settings)
    assert stats["reopened"] == 1
    detail = store.issue("CEG-1")
    assert [e["kind"] for e in detail["events"]] == ["opened", "detected", "fixed", "reopened"]
    # numbering continues after a reload
    store.ingest(
        scan("s4", minutes=30),
        [sqli(), code("semgrep", "ceg.shell-with-input", PATH, 90, "subprocess.run(cmd, shell=True)")],
        reg,
        families,
        settings,
    )
    assert {i["id"] for i in store.issues()} == {"CEG-1", "CEG-2"}


def test_duplicate_scan_ids_are_ignored(store, reg, families, settings):
    store.ingest(scan("s1"), [sqli()], reg, families, settings)
    assert store.ingest(scan("s1"), [], reg, families, settings) == {"duplicate_scan": 1}
    assert store.issues()[0]["status"] == "open"


def test_risk_acceptance_needs_and_respects_expiry(store, reg, families, settings):
    store.ingest(scan("s1"), [sqli()], reg, families, settings)
    with pytest.raises(ValueError, match="expiry"):
        store.suppress("CEG-1", Status.RISK_ACCEPTED, "compensating WAF rule", "ana", None, reg, families, settings, T0)
    with pytest.raises(ValueError, match="at most"):
        store.suppress("CEG-1", Status.RISK_ACCEPTED, "later", "ana", T0 + timedelta(days=200), reg, families, settings, T0)
    with pytest.raises(KeyError):
        store.suppress("CEG-99", Status.FALSE_POSITIVE, "nope", "ana", None, reg, families, settings, T0)
    store.suppress(
        "CEG-1", Status.RISK_ACCEPTED, "compensating WAF rule", "ana", T0 + timedelta(days=30), reg, families, settings, T0
    )
    store.ingest(scan("s2", minutes=5), [sqli()], reg, families, settings)
    assert store.issue("CEG-1")["status"] == "risk_accepted"  # still reported, still accepted
    assert store.expire_acceptances(T0 + timedelta(days=29), reg, families, settings) == []
    assert store.expire_acceptances(T0 + timedelta(days=31), reg, families, settings) == ["CEG-1"]
    assert store.issue("CEG-1")["status"] == "open"


def test_filters_and_secret_values_never_stored(store, reg, families, settings):
    from ceg.importers import secret_hash
    from ceg.models import Finding, Kind, Location, Severity

    value = "sk-proj-" + "Qw3" * 16
    f = Finding(
        tool="ceg-secrets",
        rule="openai-api-key",
        kind=Kind.SECRET,
        title="OpenAI key",
        severity=Severity.HIGH,
        location=Location("mobile/app.config.json", 3, 3, snippet="[redacted]"),
        secret_hash=secret_hash(value),
    )
    store.ingest(scan("x1", "ceg-secrets"), [f, sqli()], reg, families, settings)
    assert [i["kind"] for i in store.issues(kind="secret")] == ["secret"]
    assert len(store.issues(service="chat-api")) == 1
    with store.conn() as c:
        dump = str(c.execute("SELECT * FROM issues").fetchall()) + str(c.execute("SELECT * FROM issue_events").fetchall())
    assert value not in dump

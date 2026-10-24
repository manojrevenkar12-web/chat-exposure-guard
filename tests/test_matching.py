"""Turning detections into issues across tools, edits and scans."""

from datetime import timedelta

from ceg.importers import secret_hash
from ceg.matching import LineTracker, Scan, Status, Tracker
from ceg.models import Finding, Kind, Location, Severity
from ceg.source import SourceIndex

from .conftest import T0
from .helpers import code

SRC_V1 = '''import sqlite3


def search(cur, user_id, term):
    """Search a user's messages."""
    cur.execute(f"SELECT * FROM messages WHERE user_id = {user_id} AND text LIKE '%{term}%'")
    return cur.fetchall()
'''

SRC_V2 = '''import sqlite3
import logging

log = logging.getLogger(__name__)
# a comment block added above
# that moves every line down


def search(cur, user_id, term):
    """Search a user's messages."""
    log.debug("searching")
    cur.execute(f"SELECT * FROM messages WHERE user_id = {user_id} AND text LIKE '%{term}%'")
    return cur.fetchall()
'''


def scan(sid: str, tool: str, at_minutes: int, full: bool = True, scope: str = "repo") -> Scan:
    return Scan(sid, tool, scope, full, T0 + timedelta(minutes=at_minutes))


def write(tmp_path, name: str, text: str):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return SourceIndex(tmp_path)


def test_two_tools_one_weakness_is_one_issue(tmp_path, reg, families, settings):
    src = write(tmp_path, "services/chat-api/app/search.py", SRC_V1)
    t = Tracker(reg, families, settings)
    t.ingest(scan("s1", "semgrep", 0), [code("semgrep", "ceg.sql-built-from-input", "services/chat-api/app/search.py", 6)], src)
    t.ingest(scan("b1", "bandit", 0), [code("bandit", "B608", "services/chat-api/app/search.py", 6)], src)
    assert len(t.issues) == 1
    i = next(iter(t.issues.values()))
    assert i.tools == ["bandit", "semgrep"] and i.family == "sqli" and i.cwe == "CWE-89"
    assert i.service == "chat-api"


def test_lines_moving_does_not_create_a_new_issue_but_does_for_the_line_baseline(tmp_path, reg, families, settings):
    path = "services/chat-api/app/search.py"
    for cls, expected in ((Tracker, 1), (LineTracker, 2)):
        t = cls(reg, families, settings)
        t.ingest(scan("1", "semgrep", 0), [code("semgrep", "ceg.sql-built-from-input", path, 6)], write(tmp_path, path, SRC_V1))
        t.ingest(scan("2", "semgrep", 5), [code("semgrep", "ceg.sql-built-from-input", path, 12)], write(tmp_path, path, SRC_V2))
        assert len(t.issues) == expected, cls.__name__
        if cls is Tracker:
            i = next(iter(t.issues.values()))
            assert i.status == Status.OPEN and i.reopen_count == 0
        else:
            first = t.issues["CEG-1"]
            assert first.status == Status.FIXED  # the baseline thinks the old one was fixed and a new one appeared


def test_renamed_file_keeps_its_issue(tmp_path, reg, families, settings):
    t = Tracker(reg, families, settings)
    old, new = "services/chat-api/app/search.py", "services/chat-api/app/queries/search.py"
    t.ingest(scan("1", "semgrep", 0), [code("semgrep", "ceg.sql-built-from-input", old, 6)], write(tmp_path / "a", old, SRC_V1))
    t.ingest(
        scan("2", "semgrep", 5),
        [code("semgrep", "ceg.sql-built-from-input", new, 6)],
        write(tmp_path / "b", new, SRC_V1),
        renames={old: new},
    )
    assert len(t.issues) == 1 and next(iter(t.issues.values())).path == new


def test_moved_function_without_rename_information_is_found_by_its_line(tmp_path, reg, families, settings):
    t = Tracker(reg, families, settings)
    old, new = "services/chat-api/app/search.py", "services/chat-api/app/db/query.py"
    t.ingest(scan("1", "semgrep", 0), [code("semgrep", "ceg.sql-built-from-input", old, 6)], write(tmp_path / "a", old, SRC_V1))
    t.ingest(scan("2", "semgrep", 5), [code("semgrep", "ceg.sql-built-from-input", new, 12)], write(tmp_path / "b", new, SRC_V2))
    assert len(t.issues) == 1


def test_fixed_needs_every_reporting_tool_to_stop_and_comes_back_as_reopened(tmp_path, reg, families, settings):
    path = "services/chat-api/app/search.py"
    src = write(tmp_path, path, SRC_V1)
    t = Tracker(reg, families, settings)
    t.ingest(scan("s1", "semgrep", 0), [code("semgrep", "ceg.sql-built-from-input", path, 6)], src)
    t.ingest(scan("b1", "bandit", 0), [code("bandit", "B608", path, 6)], src)
    t.ingest(scan("s2", "semgrep", 10), [], src)
    i = t.issues["CEG-1"]
    assert i.status == Status.OPEN and i.tools == ["bandit"]
    t.ingest(scan("b2", "bandit", 10), [], src)
    assert i.status == Status.FIXED and i.fixed_at == T0 + timedelta(minutes=10)
    t.ingest(scan("s3", "semgrep", 20), [code("semgrep", "ceg.sql-built-from-input", path, 6)], src)
    assert i.status == Status.OPEN and i.reopen_count == 1 and len(t.issues) == 1
    assert [e.kind for e in i.events][-2:] == ["fixed", "reopened"]


def test_partial_scans_never_fix_anything(tmp_path, reg, families, settings):
    path = "services/chat-api/app/search.py"
    src = write(tmp_path, path, SRC_V1)
    t = Tracker(reg, families, settings)
    t.ingest(scan("1", "semgrep", 0), [code("semgrep", "ceg.sql-built-from-input", path, 6)], src)
    t.ingest(scan("pr", "semgrep", 5, full=False), [], src)
    assert t.issues["CEG-1"].status == Status.OPEN


def test_scoped_full_scan_only_resolves_its_own_service(tmp_path, reg, families, settings):
    t = Tracker(reg, families, settings)
    a = code("semgrep", "ceg.shell-with-input", "services/media-service/media.py", 3)
    b = code("semgrep", "ceg.shell-with-input", "services/chat-api/app/main.py", 3)
    t.ingest(scan("1", "semgrep", 0), [a, b])
    t.ingest(scan("2", "semgrep", 5, scope="media-service"), [])
    by_service = {i.service: i.status for i in t.issues.values()}
    assert by_service == {"media-service": Status.FIXED, "chat-api": Status.OPEN}


def test_one_secret_in_two_files_is_one_rotation(reg, families, settings):
    h = secret_hash("sk-proj-" + "a1B2" * 12)
    fs = [
        Finding("gitleaks", "openai-api-key", Kind.SECRET, "key", Severity.HIGH, Location(p, 3), secret_hash=h)
        for p in ("mobile/app.config.json", "web/src/config.ts")
    ]
    t = Tracker(reg, families, settings)
    t.ingest(scan("1", "gitleaks", 0), fs)
    assert len(t.issues) == 1 and len(next(iter(t.issues.values())).locations) == 2


def test_dependency_advisory_aliases_merge(reg, families, settings):
    def dep(ids):
        return Finding(
            "osv-scanner",
            ids[0],
            Kind.DEPENDENCY,
            "jinja2",
            Severity.MEDIUM,
            Location("services/chat-api/requirements.txt"),
            ecosystem="PyPI",
            package="Jinja2",
            version="3.1.2",
            advisory_ids=tuple(ids),
            service="chat-api",
        )

    t = Tracker(reg, families, settings)
    t.ingest(scan("1", "osv-scanner", 0), [dep(["GHSA-TEST-0001"])])
    t.ingest(scan("2", "osv-scanner", 5), [dep(["CVE-TEST-0001", "GHSA-TEST-0001"])])
    t.ingest(scan("3", "osv-scanner", 10), [dep(["CVE-TEST-0001"])])
    assert len(t.issues) == 1
    assert t.issues["CEG-1"].advisories == {"GHSA-TEST-0001", "CVE-TEST-0001"}


def test_register_raises_exposed_services_and_lowers_internal_ones(reg, families, settings):
    t = Tracker(reg, families, settings)
    t.ingest(
        scan("1", "bandit", 0),
        [
            code("bandit", "B501", "services/chat-api/app/x.py", 3, sev=Severity.HIGH),
            code("bandit", "B501", "jobs/analytics/daily.py", 3, sev=Severity.HIGH),
        ],
    )
    sev = {i.service: (i.severity, i.severity_reason) for i in t.issues.values()}
    assert sev["chat-api"][0] == Severity.CRITICAL and "internet-facing" in sev["chat-api"][1]
    assert sev["analytics"][0] == Severity.MEDIUM and "lowered" in sev["analytics"][1]
    assert t.issues["CEG-1"].due_at == T0 + timedelta(days=settings.sla_days["critical"])


def test_suppression_needs_a_reason_and_survives_new_detections(tmp_path, reg, families, settings):
    import pytest

    path = "services/chat-api/app/search.py"
    src = write(tmp_path, path, SRC_V1)
    t = Tracker(reg, families, settings)
    t.ingest(scan("1", "semgrep", 0), [code("semgrep", "ceg.sql-built-from-input", path, 6)], src)
    with pytest.raises(ValueError):
        t.suppress("CEG-1", Status.FALSE_POSITIVE, "  ", T0)
    t.suppress("CEG-1", Status.FALSE_POSITIVE, "term is an enum, never user input", T0)
    t.ingest(scan("2", "semgrep", 5), [code("semgrep", "ceg.sql-built-from-input", path, 6)], src)
    assert t.issues["CEG-1"].status == Status.FALSE_POSITIVE and len(t.issues) == 1


def test_ignored_rules_are_not_tracked(reg, families, settings):
    t = Tracker(reg, families, settings)
    t.ingest(scan("1", "bandit", 0), [code("bandit", "B404", "services/media-service/media.py", 2)])
    assert t.issues == {}


def test_two_weaknesses_of_one_family_far_apart_in_a_function_stay_two(tmp_path, reg, families, settings):
    body = (
        "def f(cur, a, b):\n"
        + "    x = 1\n" * 30
        + '    cur.execute(f"select {a}")\n'
        + "    y = 2\n" * 30
        + '    cur.execute(f"select {b}")\n'
    )
    path = "services/chat-api/app/f.py"
    src = write(tmp_path, path, body)
    t = Tracker(reg, families, settings)
    t.ingest(
        scan("1", "semgrep", 0),
        [code("semgrep", "ceg.sql-built-from-input", path, 32), code("semgrep", "ceg.sql-built-from-input", path, 63)],
        src,
    )
    assert len(t.issues) == 2

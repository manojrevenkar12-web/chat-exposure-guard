"""The project's rules with the real scanners: Semgrep's own rule tests, and the example platform
against its list of planted weaknesses (examples/companion-platform/PLANTED.yaml)."""

import shutil
import subprocess
from datetime import UTC, datetime

import pytest
import yaml

from ceg.matching import Scan, Tracker
from ceg.scanners import RULES_DIR, scan_all
from ceg.source import SourceIndex

from .conftest import EXAMPLE, need_scanners

pytestmark = pytest.mark.scanners


def test_semgrep_rule_tests():
    need_scanners()
    for lang in ("python", "js"):
        r = subprocess.run(
            [shutil.which("semgrep"), "--test", "--metrics=off", str(RULES_DIR / lang)], capture_output=True, text=True
        )
        assert r.returncode == 0, r.stdout + r.stderr


@pytest.fixture(scope="module")
def tracked(reg, families, settings):
    need_scanners()
    ss = scan_all(EXAMPLE, reg)
    assert not ss.skipped
    t = Tracker(reg, families, settings)
    now = datetime(2026, 10, 5, tzinfo=UTC)
    for tool, fs in ss.by_tool.items():
        t.ingest(Scan(f"t:{tool}", tool, "repo", True, now), fs, SourceIndex(EXAMPLE))
    return t


def planted():
    doc = yaml.safe_load((EXAMPLE / "PLANTED.yaml").read_text())
    return doc["code"] + doc["exposure"]


@pytest.mark.parametrize("item", planted(), ids=lambda i: i["id"])
def test_each_planted_weakness_is_one_issue(tracked, item):
    want = set(item["reported_by"])
    hits = [
        i
        for i in tracked.issues.values()
        if any(f"{a.tool}:{a.rule}" in want and a.path == item["path"] and a.line == item.get("line", a.line) for a in i.anchors)
    ]
    assert len(hits) == 1, f"{item['id']} {item['what']}: {len(hits)} issues"
    i = hits[0]
    assert {f"{a.tool}:{a.rule}" for a in i.anchors} == want, "every listed tool reports it, merged into one issue"
    assert i.severity.value == item["severity"], i.severity_reason


def test_nothing_else_is_reported(tracked):
    assert len(tracked.issues) == len(planted())

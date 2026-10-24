"""The held-out runner: scoring, and the first run is never rewritten."""

import json

import pytest

from ceg import heldout

from .conftest import need_scanners


def test_first_run_is_kept(tmp_path):
    r = {
        "set": "demo",
        "kind": "rules",
        "status": "held-out",
        "cases": 1,
        "weaknesses": 1,
        "found": 0,
        "missed": 1,
        "false_alarms": 0,
        "recall": 0.0,
        "precision": None,
        "safe_cases": 0,
        "safe_cases_clean": 0,
        "per_category": {},
        "case_results": [],
        "skipped": [],
    }
    out, first = heldout.record(r, tmp_path)
    assert first
    out, first = heldout.record({**r, "found": 1, "missed": 0, "recall": 1.0}, tmp_path)
    assert not first
    assert json.loads((out / "first_run.json").read_text())["recall"] == 0.0
    assert json.loads((out / "latest.json").read_text())["recall"] == 1.0


@pytest.mark.scanners
def test_scoring(tmp_path):
    need_scanners()
    s = tmp_path / "mini"
    (s / "cases" / "a1").mkdir(parents=True)
    (s / "cases" / "a2").mkdir(parents=True)
    (s / "cases" / "a1" / "job.py").write_text("import requests\n\nrequests.get('https://x.example', verify=False, timeout=3)\n")
    (s / "cases" / "a2" / "job.py").write_text("import requests\n\nrequests.get('https://x.example', timeout=3)\n")
    (s / "answers.yaml").write_text("cases:\n  - {id: a1, expect: [tls-verification-off, sqli]}\n  - {id: a2, expect: []}\n")
    r = heldout.run_rules(s)
    assert (r["found"], r["missed"], r["false_alarms"], r["safe_cases_clean"]) == (1, 1, 0, 1)
    assert r["per_category"]["tls-verification-off"] == {"tp": 1, "fn": 0, "fp": 0}  # semgrep + bandit count once
    assert "a1" in heldout.rules_markdown(r)

"""Held-out sets: cases written by someone who had not seen the rules or the defences.

A set's first run is the honest number and is never rewritten: it is saved to
``reports/heldout/<set>/first_run.json`` (and ``FIRST_RUN.md``) the first time the set runs, and
every later run goes to ``latest.json``. Once anyone studies a set's failures to change the code, the
set becomes a regression set (``heldout/<set>/STATUS`` = regression) and a new one is written from
the guide by someone who has not seen the code.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from . import register as register_mod
from .aisec import harness
from .matching import Scan, Tracker
from .scanners import scan_all
from .settings import ROOT, Families, load_families, load_settings
from .source import SourceIndex

REPORTS = ROOT / "reports" / "heldout"

# The categories of heldout/WRITING_CASES.md (family names in config/rule_families.yaml).
CATEGORIES = (
    "chat-idor",
    "chat-content-logged",
    "sqli",
    "command-injection",
    "tls-verification-off",
    "unsafe-deserialization",
    "jwt-unverified",
    "untrusted-text-in-system-prompt",
    "broker-without-auth",
    "long-lived-media-url",
    "cors-credentials-wildcard",
    "model-output-as-html",
    "markdown-image-exfiltration",
    "hardcoded-credential",
    "datastore-exposed",
    "database-rules-public",
    "bucket-public",
)


def status(set_dir: Path) -> str:
    p = set_dir / "STATUS"
    return p.read_text().strip() if p.exists() else "held-out"


def run_rules(set_dir: Path, families: Families | None = None) -> dict[str, Any]:
    """Scan every case on its own, track the findings as the product would (one issue per weakness,
    ignored rules dropped) and compare the issues' categories with the answers. Issues outside the
    guide's categories (for example Bandit's generic subprocess import warning) are listed apart:
    the answers say nothing about them, so they are neither hits nor false alarms."""
    fam = families or load_families()
    st = load_settings()
    known = set(CATEGORIES)
    answers = yaml.safe_load((set_dir / "answers.yaml").read_text())["cases"]
    tp: Counter[str] = Counter()
    fn: Counter[str] = Counter()
    fp: Counter[str] = Counter()
    other: Counter[str] = Counter()
    cases = []
    skipped: set[str] = set()
    now = datetime(2026, 1, 1, tzinfo=UTC)
    for a in answers:
        case_dir = set_dir / "cases" / a["id"]
        reg_file = case_dir / "register.yaml"
        reg = register_mod.load(reg_file) if reg_file.exists() else None
        ss = scan_all(case_dir, reg)
        skipped |= set(ss.skipped)
        t = Tracker(reg, fam, st)
        for tool, fs in ss.by_tool.items():
            t.ingest(Scan(f"{a['id']}:{tool}", tool, "repo", True, now), fs, SourceIndex(case_dir))
        fams = Counter(i.family for i in t.issues.values())
        found = Counter({k: v for k, v in fams.items() if k in known})
        other.update({k: v for k, v in fams.items() if k not in known})
        expect = Counter(a.get("expect") or [])
        for cat in set(found) | set(expect):
            hit = min(found[cat], expect[cat])
            tp[cat] += hit
            fn[cat] += expect[cat] - hit
            fp[cat] += found[cat] - hit
        cases.append(
            {
                "id": a["id"],
                "expect": sorted(expect.elements()),
                "found": sorted(found.elements()),
                "ok": found == expect,
                "note": a.get("note", ""),
            }
        )
    cats = sorted(set(tp) | set(fn) | set(fp))
    per = {c: {"tp": tp[c], "fn": fn[c], "fp": fp[c]} for c in cats}
    T, N, P = sum(tp.values()), sum(fn.values()), sum(fp.values())
    safe = [c for c in cases if not c["expect"]]
    return {
        "set": set_dir.name,
        "kind": "rules",
        "status": status(set_dir),
        "cases": len(cases),
        "weaknesses": T + N,
        "found": T,
        "missed": N,
        "false_alarms": P,
        "recall": round(T / (T + N), 3) if T + N else None,
        "precision": round(T / (T + P), 3) if T + P else None,
        "safe_cases": len(safe),
        "safe_cases_clean": sum(1 for c in safe if not c["found"]),
        "per_category": per,
        "case_results": cases,
        "skipped": sorted(skipped),
    }


def run_aisec(set_dir: Path) -> dict[str, Any]:
    rep = harness.evaluate(harness.load_cases(set_dir / "attacks.yaml"), harness.load_cases(set_dir / "benign.yaml"))
    return {
        "set": set_dir.name,
        "kind": "aisec",
        "status": status(set_dir),
        "attacks": rep.attacks,
        "benign": rep.benign,
        "rows": rep.rows,
        "failures": rep.failures,
        "markdown": harness.markdown(rep, f"Held-out set {set_dir.name}"),
    }


def rules_markdown(r: dict[str, Any]) -> str:
    lines = [
        f"## Held-out set {r['set']} (code and configuration)",
        "",
        f"{r['cases']} cases, {r['weaknesses']} planted weaknesses, {r['safe_cases']} safe look-alikes.",
        "",
        f"- Found {r['found']} of {r['weaknesses']} (recall {r['recall']})",
        f"- {r['false_alarms']} false alarms (precision {r['precision']})",
        f"- Safe cases with no finding: {r['safe_cases_clean']} of {r['safe_cases']}",
        "",
        "| Category | Found | Missed | False alarms |",
        "|---|---|---|---|",
    ]
    for c, v in r["per_category"].items():
        lines.append(f"| {c} | {v['tp']} | {v['fn']} | {v['fp']} |")
    wrong = [c for c in r["case_results"] if not c["ok"]]
    if wrong:
        lines += ["", "Cases that came out wrong:", ""]
        for c in wrong:
            lines.append(f"- {c['id']}: expected {c['expect'] or 'nothing'}, found {c['found'] or 'nothing'} ({c['note']})")
    if r.get("outside_categories"):
        lines += [
            "",
            "Also reported, outside the set's categories (not scored): "
            + ", ".join(f"{k} ×{v}" for k, v in sorted(r["outside_categories"].items())),
        ]
    if r["skipped"]:
        lines += ["", "Not run: " + "; ".join(r["skipped"])]
    return "\n".join(lines) + "\n"


def record(result: dict[str, Any], reports: Path = REPORTS) -> tuple[Path, bool]:
    """Save a run. The first run of a set is kept forever; later runs only update latest.json."""
    out = reports / result["set"]
    out.mkdir(parents=True, exist_ok=True)
    result = {**result, "at": datetime.now(UTC).isoformat(timespec="seconds")}
    md = result.pop("markdown", None) or (rules_markdown(result) if result["kind"] == "rules" else "")
    first = out / "first_run.json"
    is_first = not first.exists()
    if is_first:
        first.write_text(json.dumps(result, indent=2) + "\n")
        (out / "FIRST_RUN.md").write_text(f"<!-- first run {result['at']}; never rewritten -->\n" + md)
    (out / "latest.json").write_text(json.dumps(result, indent=2) + "\n")
    (out / "LATEST.md").write_text(md)
    return out, is_first

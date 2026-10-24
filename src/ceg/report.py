"""The risk register view and the weekly security update.

Residual risk per service is its inherent risk (impact × likelihood from the register) weighted by
what is still open there. The weekly update is the company-wide broadcast the role asks for: what is
new, what is late, what got fixed, and where the risk sits.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any

from .matching import Issue, Status
from .models import Severity
from .register import Register

WEIGHT = {"critical": 1.0, "high": 0.5, "medium": 0.2, "low": 0.05, "info": 0.0}


def register_view(reg: Register, issues: list[Issue], now: datetime) -> list[dict[str, Any]]:
    by_service: dict[str, list[Issue]] = defaultdict(list)
    for i in issues:
        if i.status == Status.OPEN:
            by_service[i.service].append(i)
    rows = []
    for s in reg.services:
        open_ = by_service.get(s.name, [])
        sev = Counter(i.severity.value for i in open_)
        pressure = min(1.0, sum(WEIGHT[i.severity.value] for i in open_))
        rows.append(
            {
                "service": s.name,
                "owner": s.owner,
                "exposure": s.exposure.value,
                "data": sorted({d.value for d in s.data} | {d.value for ds in s.datastores for d in ds.data}),
                "inherent_risk": s.inherent_risk,
                # an empty service still carries a fifth of its inherent risk: no scan sees everything
                "residual_risk": round(s.inherent_risk * (0.2 + 0.8 * pressure), 1),
                "open": dict(sev),
                "overdue": sum(1 for i in open_ if i.due_at < now),
                "last_pentest": s.last_pentest or "never",
            }
        )
    unowned = by_service.get("", [])
    if unowned:
        rows.append(
            {
                "service": "(not in the register)",
                "owner": "-",
                "exposure": "?",
                "data": [],
                "inherent_risk": 0,
                "residual_risk": 0,
                "open": dict(Counter(i.severity.value for i in unowned)),
                "overdue": sum(1 for i in unowned if i.due_at < now),
                "last_pentest": "-",
            }
        )
    return sorted(rows, key=lambda r: -r["residual_risk"])


def weekly(reg: Register, issues: list[Issue], now: datetime, notes: list[str] | None = None) -> str:
    week = now - timedelta(days=7)
    opened = [i for i in issues if i.first_seen >= week]
    fixed = [i for i in issues if i.fixed_at and i.fixed_at >= week]
    open_ = [i for i in issues if i.status == Status.OPEN]
    overdue = sorted((i for i in open_ if i.due_at < now), key=lambda i: (-i.severity.rank, i.due_at))
    top_new = sorted(
        (i for i in opened if i.status == Status.OPEN and i.severity.rank >= Severity.HIGH.rank),
        key=lambda i: (-i.severity.rank, i.id),
    )
    lines = [f"# Security update, week of {week.date()}", ""]
    lines.append(f"{len(opened)} new, {len(fixed)} fixed, {len(open_)} open ({len(overdue)} past their due date).")
    lines.append("")
    if top_new:
        lines += ["## New and serious", ""]
        for i in top_new[:10]:
            lines.append(f"- **{i.severity.value}** {i.title} ({i.service or 'no owner in the register'}), due {i.due_at.date()}")
        lines.append("")
    if overdue:
        lines += ["## Late", ""]
        for i in overdue[:10]:
            lines.append(f"- {i.id} **{i.severity.value}** {i.title}: {(now - i.due_at).days} days late ({i.service or '-'})")
        lines.append("")
    if fixed:
        lines += ["## Fixed this week", ""]
        lines += [f"- {i.title} ({i.service or '-'})" for i in sorted(fixed, key=lambda i: -i.severity.rank)[:10]]
        lines.append("")
    lines += [
        "## Where the risk sits",
        "",
        "| Service | Exposure | Holds | Open (crit/high) | Residual risk |",
        "|---|---|---|---|---|",
    ]
    for r in register_view(reg, issues, now)[:8]:
        o = r["open"]
        lines.append(
            f"| {r['service']} | {r['exposure']} | {', '.join(r['data'])} | {o.get('critical', 0)}/{o.get('high', 0)} | "
            f"{r['residual_risk']} of {r['inherent_risk']} |"
        )
    if notes:
        lines += ["", "## Threats to know about", ""] + [f"- {n}" for n in notes]
    return "\n".join(lines) + "\n"

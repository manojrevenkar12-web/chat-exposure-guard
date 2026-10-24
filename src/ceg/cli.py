"""Command line: ``ceg --help``."""

from __future__ import annotations

import json
import os
from datetime import UTC, date, datetime
from pathlib import Path

import typer

from . import access as access_mod
from . import importers
from . import register as register_mod
from .aisec import harness
from .matching import Scan, Status, Tracker
from .models import Severity
from .report import register_view, weekly
from .review import comment, review
from .scanners import scan_all
from .settings import load_families, load_settings
from .source import SourceIndex
from .store import Store

app = typer.Typer(add_completion=False, help="Every path to users' private chats: found, deduplicated, prioritised, tracked.")
alerts_app = typer.Typer(help="Security alert escalation.")
app.add_typer(alerts_app, name="alerts")


def _store() -> Store:
    dsn = os.environ.get("CEG_DATABASE_URL")
    if not dsn:
        typer.echo("CEG_DATABASE_URL is not set", err=True)
        raise typer.Exit(2)
    return Store(dsn)


def _now() -> datetime:
    return datetime.now(UTC)


@app.command()
def migrate() -> None:
    """Apply database migrations."""
    applied = _store().migrate()
    typer.echo(f"applied: {', '.join(applied) or 'nothing new'}")


@app.command()
def scan(
    target: Path = typer.Argument(..., help="checkout to scan"),
    register: Path = typer.Option(..., help="risk register YAML"),
    scope: str = typer.Option("repo", help="service name, or repo for everything"),
    commit: str = typer.Option("", help="commit the checkout is at"),
    dry_run: bool = typer.Option(False, help="print findings instead of recording them"),
    fail_on: str = typer.Option("", help="exit 1 if an open issue at this severity or above exists"),
) -> None:
    """Run Semgrep (project rules), Bandit, the secret scanner and the exposure checks, and record the results."""
    reg = register_mod.load(register)
    ss = scan_all(target, reg)
    for s in ss.skipped:
        typer.echo(f"skipped: {s}", err=True)
    fam, st = load_families(), load_settings()
    if dry_run:
        t = Tracker(reg, fam, st)
        for tool, fs in ss.by_tool.items():
            t.ingest(Scan(f"dry:{tool}", tool, scope, True, _now(), commit), fs, SourceIndex(target))
        for i in t.open_issues():
            typer.echo(f"{i.severity.value:8} {i.id:8} {i.service or '-':14} {i.title}  [{', '.join(i.tools)}]")
        typer.echo(f"{len(t.open_issues())} issues from {len(ss.all)} findings")
        _gate(t.open_issues(), fail_on)
        return
    store = _store()
    for tool, fs in ss.by_tool.items():
        stats = store.ingest(
            Scan(f"{tool}:{scope}:{commit or _now().isoformat()}", tool, scope, True, _now(), commit),
            fs,
            reg,
            fam,
            st,
            SourceIndex(target),
        )
        typer.echo(f"{tool}: {json.dumps(stats)}")
    _gate(list(store.tracker(reg, fam, st).open_issues()), fail_on)


def _gate(issues: list, fail_on: str) -> None:  # type: ignore[type-arg]
    if not fail_on:
        return
    threshold = Severity(fail_on)
    bad = [i for i in issues if i.severity.rank >= threshold.rank]
    if bad:
        typer.echo(f"{len(bad)} open issue(s) at {fail_on} or above", err=True)
        raise typer.Exit(1)


@app.command("import")
def import_(
    fmt: str = typer.Argument(..., help=f"one of {sorted(importers.FORMATS)}"),
    report: Path = typer.Argument(...),
    register: Path = typer.Option(...),
    scope: str = typer.Option("repo"),
    partial: bool = typer.Option(False, help="a partial scan never marks anything fixed"),
    commit: str = typer.Option(""),
    source_root: Path | None = typer.Option(None, help="checkout the report was produced from (better matching)"),
) -> None:
    """Import a report: Semgrep, SARIF, Bandit, OSV-Scanner, gitleaks, ZAP, a pentest, or AI provider advisories.

    A provider-advisories file lists the advisories still open; removing one marks its issues fixed.
    """
    reg = register_mod.load(register)
    extra = {"register": reg} if fmt == "provider-advisories" else {}
    findings = importers.load(fmt, report, root=str(source_root or ""), **extra)
    tool = findings[0].tool if findings else fmt
    stats = _store().ingest(
        Scan(f"{tool}:{scope}:{commit or report.name}", tool, scope, not partial, _now(), commit),
        findings,
        reg,
        load_families(),
        load_settings(),
        SourceIndex(source_root) if source_root else None,
    )
    typer.echo(json.dumps(stats))


@app.command("review")
def review_cmd(
    repo: Path = typer.Option(Path("."), help="git repository"),
    base: str = typer.Option("origin/main"),
    head: str = typer.Option("HEAD"),
    register: Path = typer.Option(...),
    subdir: str = typer.Option("", help="scan only this directory of the repository"),
    fail_on: str = typer.Option("high"),
    out: Path | None = typer.Option(None, help="write the pull-request comment here"),
) -> None:
    """Security review of a pull request: what it introduces, not what it moved."""
    threshold = Severity(fail_on)
    res = review(repo, base, head, register_mod.load(register), load_families(), load_settings(), subdir)
    text = comment(res, threshold)
    if out:
        out.write_text(text)
    typer.echo(text)
    if res.blocking(threshold):
        raise typer.Exit(1)


@app.command()
def issues(status: str = "open", service: str = "", severity: str = "") -> None:
    """List issues from the database."""
    for i in _store().issues(status or None, service or None, severity or None):
        typer.echo(f"{i['severity']:8} {i['id']:9} due {i['due_at'][:10]}  {i['service'] or '-':14} {i['title']}")


@app.command()
def suppress(
    issue_id: str,
    status: str = typer.Option(...),
    reason: str = typer.Option(...),
    actor: str = typer.Option(...),
    until: str = typer.Option("", help="YYYY-MM-DD, required for risk_accepted"),
    register: Path = typer.Option(...),
) -> None:
    """Accept a risk (until a date) or mark a false positive, with a reason."""
    u = datetime.fromisoformat(until).replace(tzinfo=UTC) if until else None
    _store().suppress(
        issue_id, Status(status), reason, actor, u, register_mod.load(register), load_families(), load_settings(), _now()
    )
    typer.echo(f"{issue_id}: {status}")


@app.command("register")
def register_cmd(register: Path, db: bool = typer.Option(True, help="include open issues from the database")) -> None:
    """Validate the risk register and show inherent and residual risk per service."""
    reg = register_mod.load(register)
    issues_ = list(_store().tracker(reg, load_families(), load_settings()).issues.values()) if db else []
    for r in register_view(reg, issues_, _now()):
        typer.echo(
            f"{r['service']:16} {r['exposure']:9} risk {r['residual_risk']:>5} / {r['inherent_risk']:<3} "
            f"open {r['open']}  pentest {r['last_pentest']}"
        )


@app.command()
def report(register: Path = typer.Option(...), out: Path | None = None) -> None:
    """The weekly security update (Markdown)."""
    reg = register_mod.load(register)
    text = weekly(reg, list(_store().tracker(reg, load_families(), load_settings()).issues.values()), _now())
    if out:
        out.write_text(text)
    typer.echo(text)


@app.command()
def access(
    directory: Path,
    today: str = typer.Option("", help="YYYY-MM-DD; default today"),
    register: Path | None = typer.Option(None, help="record findings in the database"),
    json_out: bool = False,
) -> None:
    """Access review: leavers with access, accounts without owners, admins without MFA, devices."""
    day = date.fromisoformat(today) if today else _now().date()
    fs = access_mod.review(directory, day)
    if register:
        stats = _store().ingest(
            Scan(f"ceg-access:{day}", "ceg-access", access_mod.SERVICE, True, _now()),
            fs,
            register_mod.load(register),
            load_families(),
            load_settings(),
        )
        typer.echo(json.dumps(stats))
    elif json_out:
        typer.echo(
            json.dumps(
                [{"rule": f.rule, "severity": f.severity.value, "resource": f.resource, "title": f.title} for f in fs], indent=2
            )
        )
    else:
        for f in sorted(fs, key=lambda f: -f.severity.rank):
            typer.echo(f"{f.severity.value:8} {f.rule:28} {f.title}")


@app.command("aisec")
def aisec_cmd(
    attacks: Path = typer.Option(Path("aisec/dev-attacks.yaml")),
    benign: Path = typer.Option(Path("aisec/benign.yaml")),
    out: Path | None = None,
    title: str = "Prompt-injection outcomes",
) -> None:
    """Run attacks and benign conversations through the companion pipeline under each set of defences."""
    rep = harness.evaluate(harness.load_cases(attacks), harness.load_cases(benign))
    text = harness.markdown(rep, title)
    if out:
        out.write_text(text)
    typer.echo(text)
    if rep.rows[-1]["attack_success"] or rep.rows[-1]["benign_ok"] < rep.rows[-1]["benign"]:
        raise typer.Exit(1)


@app.command("heldout")
def heldout_cmd(set_dir: Path = typer.Argument(..., help="heldout/<set>")) -> None:
    """Run a held-out set and record it (the first run is kept as the honest number)."""
    from . import heldout as ho

    if (set_dir / "answers.yaml").exists():
        res = ho.run_rules(set_dir)
        text = ho.rules_markdown(res)
    else:
        res = ho.run_aisec(set_dir)
        text = res["markdown"]
    out, first = ho.record(res)
    typer.echo(text)
    typer.echo(f"{'first run recorded' if first else 'latest run recorded'} in {out}")


@alerts_app.command("tick")
def alerts_tick() -> None:
    """Escalate unacknowledged alerts whose wait is over (run every minute)."""
    from .alerts import AlertDesk, OnCall, RecordingNotifier, SlackNotifier

    slack = os.environ.get("CEG_SLACK_WEBHOOK_URL")
    desk = AlertDesk(_store(), OnCall.load(), SlackNotifier(slack) if slack else RecordingNotifier())
    typer.echo(json.dumps({"escalated": desk.tick(_now())}))


@app.command()
def serve(host: str = "0.0.0.0", port: int = 8000) -> None:  # noqa: S104
    """Run the API."""
    import uvicorn

    uvicorn.run("ceg.api:app_from_env", host=host, port=port, factory=True)


def main() -> None:  # pragma: no cover
    app(prog_name="ceg")


if __name__ == "__main__":  # pragma: no cover
    main()

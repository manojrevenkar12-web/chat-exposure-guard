"""Deduplication benchmark: one repository history, three ways of deciding "same issue".

The example platform is committed to a fresh git repository and then changed the way real code
changes: lines shift, a file is reformatted, a module is renamed, a route moves to another file, a
function is renamed. Twice a weakness is really fixed, once a fix is reverted, and once a new
weakness arrives. After every commit Semgrep, Bandit, the secret scanner and the exposure checks
scan the checkout, and each tracker ingests the results.

The truth is in STEPS: what each commit really did. Anything a tracker opens, fixes or reopens
beyond that is an error a security team would have to triage by hand.

    python bench/dedup.py            # writes reports/dedup_benchmark.md and .json
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ceg import register as register_mod
from ceg.matching import Detection, Issue, LineTracker, Scan, Status, Tracker
from ceg.models import Kind
from ceg.review import changes
from ceg.scanners import scan_all
from ceg.settings import load_families, load_settings
from ceg.source import SourceIndex

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "companion-platform"
REPORTS = ROOT / "reports"


METRICS = ("false new issues", "missed new weaknesses", "false fixes", "missed fixes", "false reopens", "missed reopens")


class SnippetTracker(Tracker):
    """The other common default: (tool, rule, path, hash of the flagged line). Survives lines moving
    but not reformatting, renamed files, moved functions or a second tool."""

    def _match_code(self, d: Detection, taken: set[tuple[str, str]]) -> Issue | None:
        f = d.finding
        for i in self.issues.values():
            if (
                i.kind == Kind.CODE
                and (i.id, f.tool) not in taken
                and i.path == d.path
                and any(a.tool == f.tool and a.rule == f.rule and a.snippet == d.snippet for a in i.anchors)
            ):
                return i
        return None

    def resolve(self, f: Any, source: SourceIndex) -> Detection:
        d = super().resolve(f, source)
        d.family = f"{f.tool}:{f.rule}"
        return d


# -- the history ------------------------------------------------------------------------------------


def edit(repo: Path, path: str, fn: Callable[[str], str]) -> None:
    p = repo / path
    new = fn(p.read_text())
    if new == p.read_text():
        raise RuntimeError(f"edit to {path} changed nothing")
    p.write_text(new)


def add_logging(repo: Path) -> None:
    edit(
        repo,
        "services/chat-api/app/main.py",
        lambda s: s.replace(
            'logger = logging.getLogger("chat-api")\n',
            'logger = logging.getLogger("chat-api")\n'
            'REQUEST_LOG_FIELDS = ("method", "path", "status", "duration_ms")\n\n\n'
            "def log_request(method, path, status, duration_ms):\n"
            '    logger.info("%s %s %s %.1fms", method, path, status, duration_ms)\n\n\n',
        ),
    )


def reformat_media(repo: Path) -> None:
    def fmt(s: str) -> str:
        s = s.replace(
            '    return s3.generate_presigned_url("get_object", Params={"Bucket": BUCKET, "Key": key}, ExpiresIn=604800)',
            '    return s3.generate_presigned_url(\n        "get_object",\n        Params={"Bucket": BUCKET, "Key": key},\n'
            "        ExpiresIn=604800,\n    )",
        )
        s = s.replace(
            '    r = requests.post("https://moderation.partner.example/v1/check", json={"url": image_url}, verify=False, timeout=10)',
            '    r = requests.post(\n        "https://moderation.partner.example/v1/check",\n        json={"url": image_url},\n'
            "        verify=False,\n        timeout=10,\n    )",
        )
        return s.replace("import requests\n", "import requests\n\nTIMEOUT_S = 10\n")

    edit(repo, "services/media-service/media.py", fmt)


def rename_module(repo: Path) -> None:
    git(repo, "mv", "services/media-service/media.py", "services/media-service/processing.py")
    edit(repo, "services/media-service/processing.py", lambda s: '"""Media processing for chat attachments."""\n\n' + s)


ROUTE = """@app.get("/conversations/{conversation_id}")
async def get_conversation(conversation_id: str, user=Depends(current_user), db=Depends(session)):
    conv = await db.get(Conversation, conversation_id)
    if conv is None:
        raise HTTPException(404)
    return conv


"""


def move_route(repo: Path) -> None:
    edit(
        repo,
        "services/chat-api/app/main.py",
        lambda s: (
            s.replace(ROUTE, "")
            .replace("from .llm import reply_to\n", "from .llm import reply_to\nfrom .routes import conversations\n")
            .replace('allow_methods=["*"])\n', 'allow_methods=["*"])\napp.include_router(conversations.router)\n')
        ),
    )
    p = repo / "services/chat-api/app/routes"
    p.mkdir()
    (p / "__init__.py").write_text("")
    (p / "conversations.py").write_text(
        "from fastapi import APIRouter, Depends, HTTPException\n\nfrom ..auth import current_user\n"
        "from ..db import Conversation, session\n\nrouter = APIRouter()\napp = router\n\n\n" + ROUTE.rstrip() + "\n"
    )


def rename_function(repo: Path) -> None:
    edit(repo, "services/chat-api/app/main.py", lambda s: s.replace("def search(q", "def search_messages(q"))


def trailing_comment(repo: Path) -> None:
    edit(
        repo,
        "services/chat-api/app/main.py",
        lambda s: re.sub(r"(cur\.execute\(f\"SELECT id, content.*\"\))", r"\1  # TODO: paginate", s),
    )


def fix_tls(repo: Path) -> None:
    edit(repo, "services/media-service/processing.py", lambda s: s.replace("verify=False", "verify=True"))


def revert_tls(repo: Path) -> None:
    edit(repo, "services/media-service/processing.py", lambda s: s.replace("verify=True", "verify=False"))


def new_export(repo: Path) -> None:
    edit(
        repo,
        "services/chat-api/app/main.py",
        lambda s: (
            s
            + """

@app.get("/export/{conversation_id}")
async def export_conversation(conversation_id: str, user=Depends(current_user), db=Depends(session)):
    conv = await db.get(Conversation, conversation_id)
    return {"messages": [m.content for m in conv.messages]}
"""
        ),
    )


def fix_jwt(repo: Path) -> None:
    edit(
        repo,
        "services/chat-api/app/auth.py",
        lambda s: s.replace(
            'jwt.decode(token, options={"verify_signature": False})',
            'jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"], audience="chat-api")',
        ).replace("from .db import User, sync_session\n", "from .db import User, sync_session\nfrom .keys import PUBLIC_KEY\n"),
    )


@dataclass(frozen=True)
class Step:
    name: str
    change: Callable[[Path], None] | None
    new: int = 0
    fixed: int = 0
    reopened: int = 0


STEPS = [
    Step("initial commit", None, new=29),
    Step("add request logging above the routes (lines shift)", add_logging),
    Step("reformat media.py (long calls split over lines)", reformat_media),
    Step("rename media.py to processing.py", rename_module),
    Step("move GET /conversations/{id} to routes/conversations.py", move_route),
    Step("rename search() to search_messages()", rename_function),
    Step("add a trailing comment to the SQL line", trailing_comment),
    Step("fix: verify TLS in processing.py", fix_tls, fixed=1),
    Step("revert the TLS fix", revert_tls, reopened=1),
    Step("new export endpoint without an owner check", new_export, new=1),
    Step("fix: verify JWT signatures", fix_jwt, fixed=1),
]


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=bench", "-c", "user.email=bench@ceg.example", *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


# -- run --------------------------------------------------------------------------------------------


def run() -> dict[str, Any]:
    reg = register_mod.load(EXAMPLE / "register.yaml")
    fam, st = load_families(), load_settings()
    trackers: dict[str, Tracker] = {
        "chat-exposure-guard": Tracker(reg, fam, st),
        "tool + rule + path + line": LineTracker(reg, fam, st),
        "tool + rule + path + line text": SnippetTracker(reg, fam, st),
    }
    rows: dict[str, list[dict[str, int]]] = {k: [] for k in trackers}
    t0 = datetime(2026, 10, 1, tzinfo=UTC)
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td) / "platform"
        shutil.copytree(EXAMPLE, repo, ignore=shutil.ignore_patterns("PLANTED.yaml", "README.md"))
        git(repo, "init", "-q", "-b", "main")
        for n, step in enumerate(STEPS):
            if step.change:
                step.change(repo)
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", step.name)
            renames = {}
            if n:
                renames = {c.old_path: c.path for c in changes(repo, "HEAD~1", "HEAD") if c.status == "R"}
            ss = scan_all(repo, reg)
            if ss.skipped:
                raise RuntimeError(f"scanners missing: {ss.skipped}")
            at = t0 + timedelta(hours=n)
            for name, t in trackers.items():
                before = {iid: (i.status, i.reopen_count) for iid, i in t.issues.items()}
                if renames:
                    t.apply_renames(renames, Scan(f"{n}:renames", "git", "repo", False, at))
                for tool in sorted(set(ss.by_tool) | {"semgrep", "bandit", "ceg-secrets", "ceg-exposure"}):
                    t.ingest(Scan(f"{n}:{tool}", tool, "repo", True, at), ss.by_tool.get(tool, []), SourceIndex(repo))
                opened = sum(1 for iid in t.issues if iid not in before)
                fixed = sum(
                    1
                    for iid, i in t.issues.items()
                    if iid in before and i.status == Status.FIXED and before[iid][0] != Status.FIXED
                )
                reopened = sum(1 for iid, i in t.issues.items() if iid in before and i.reopen_count > before[iid][1])
                rows[name].append(
                    {
                        "opened": opened,
                        "fixed": fixed,
                        "reopened": reopened,
                        "open": sum(1 for i in t.issues.values() if i.status == Status.OPEN),
                    }
                )
    true_open = sum(s.new for s in STEPS) - sum(s.fixed for s in STEPS) + sum(s.reopened for s in STEPS)
    summary = {}
    for name, rs in rows.items():
        e = dict.fromkeys(METRICS, 0)
        for s, r in zip(STEPS, rs, strict=True):
            e["false new issues"] += max(0, r["opened"] - s.new)
            e["missed new weaknesses"] += max(0, s.new - r["opened"])
            e["false fixes"] += max(0, r["fixed"] - s.fixed)
            e["missed fixes"] += max(0, s.fixed - r["fixed"])
            e["false reopens"] += max(0, r["reopened"] - s.reopened)
            e["missed reopens"] += max(0, s.reopened - r["reopened"])
        summary[name] = {**e, "open at the end": rs[-1]["open"], "true open": true_open}
    return {
        "steps": [s.name for s in STEPS],
        "expected": [{"new": s.new, "fixed": s.fixed, "reopened": s.reopened} for s in STEPS],
        "rows": rows,
        "summary": summary,
        "generated": datetime.now(UTC).isoformat(timespec="seconds"),
    }


def markdown(res: dict[str, Any]) -> str:
    names = list(res["rows"])
    out = [
        "# Deduplication benchmark",
        "",
        "One history of the example platform, scanned after every commit by Semgrep (project rules), Bandit, the "
        "secret scanner and the exposure checks. Three trackers ingest the same results; git renames are given to all "
        "three. The truth column says what the commit really did.",
        "",
        "| Tracker | "
        + " | ".join(m.capitalize() for m in METRICS)
        + f" | Open at the end (truth {res['summary'][names[0]]['true open']}) |",
        "|---|" + "---|" * (len(METRICS) + 1),
    ]
    for n in names:
        sm = res["summary"][n]
        out.append(f"| {n} | " + " | ".join(str(sm[m]) for m in METRICS) + f" | {sm['open at the end']} |")
    out += [
        "",
        "## Step by step",
        "",
        "Each cell is opened / fixed / reopened.",
        "",
        "| Commit | Truth | " + " | ".join(names) + " |",
        "|---|---|" + "---|" * len(names),
    ]
    for k, step in enumerate(res["steps"]):
        e = res["expected"][k]
        cells = [f"{res['rows'][n][k]['opened']} / {res['rows'][n][k]['fixed']} / {res['rows'][n][k]['reopened']}" for n in names]
        out.append(f"| {step} | {e['new']} / {e['fixed']} / {e['reopened']} | " + " | ".join(cells) + " |")
    out += [
        "",
        "What the errors cost: a false new issue is a duplicate somebody triages and closes, with a fresh due date; "
        "a false fix makes a weakness that is still there disappear from the dashboard and its SLA clock; a missed new "
        "weakness is merged into an old issue and never reviewed; a missed reopen loses the history of a regression. "
        "Bandit and Semgrep reporting the same line are two issues for both baselines, so they also count one real fix "
        "twice.",
        "",
        "Limits: one history of one example, eleven commits written by the author of the tracker. The point is the "
        "kind of change each approach survives, not a rate to quote.",
        "",
        f"Generated {res['generated']} by `python bench/dedup.py`.",
    ]
    return "\n".join(out) + "\n"


def main() -> int:
    res = run()
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "dedup_benchmark.json").write_text(json.dumps(res, indent=2) + "\n")
    (REPORTS / "dedup_benchmark.md").write_text(markdown(res))
    print(markdown(res))
    ours = res["summary"]["chat-exposure-guard"]
    return 1 if any(ours[m] for m in METRICS) else 0


if __name__ == "__main__":
    sys.exit(main())

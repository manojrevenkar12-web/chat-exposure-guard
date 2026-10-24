"""Pull-request review on a real git history: a refactor that moves code is not new; a new hole is."""

import shutil
import subprocess

import pytest

from ceg.models import Severity
from ceg.review import comment, review

from .conftest import EXAMPLE, need_scanners

pytestmark = pytest.mark.scanners


def git(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t.example", *args], check=True, capture_output=True
    )


@pytest.fixture
def repo(tmp_path):
    need_scanners()
    r = tmp_path / "repo"
    shutil.copytree(EXAMPLE / "services", r / "services")
    shutil.copy(EXAMPLE / "register.yaml", r / "register.yaml")
    git(r, "init", "-q", "-b", "main")
    git(r, "add", ".")
    git(r, "commit", "-qm", "base")
    return r


def test_refactor_with_one_new_hole(repo, reg, families, settings):
    media = repo / "services/media-service/media.py"
    text = media.read_text()
    # Refactor: rename the module, add a header that moves every line, reformat nothing else.
    (repo / "services/media-service/processing.py").write_text('"""Media processing."""\n# moved from media.py\n\n' + text)
    git(repo, "rm", "-q", "services/media-service/media.py")
    # And one real new problem in the chat API.
    main = repo / "services/chat-api/app/main.py"
    main.write_text(
        main.read_text()
        + """

@app.get("/export/{conversation_id}")
async def export_conversation(conversation_id: str, user=Depends(current_user), db=Depends(session)):
    conv = await db.get(Conversation, conversation_id)
    return conv
"""
    )
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "refactor media, add export")
    res = review(repo, "HEAD~1", "HEAD", reg, families, settings)
    assert [(i.family, i.symbol) for i in res.introduced] == [("chat-idor", "export_conversation")]
    assert res.introduced[0].severity == Severity.CRITICAL
    assert res.fixed == [] and res.unchanged > 0
    text = comment(res, Severity.HIGH)
    assert "1 new finding(s) at high or above block this merge" in text and "export" in text


def test_a_fix_is_reported_as_fixed(repo, reg, families, settings):
    media = repo / "services/media-service/media.py"
    media.write_text(media.read_text().replace("verify=False", "verify=True"))
    git(repo, "commit", "-qam", "verify TLS")
    res = review(repo, "HEAD~1", "HEAD", reg, families, settings)
    assert res.introduced == [] and [i.family for i in res.fixed] == ["tls-verification-off"]
    assert "No new findings" in comment(res, Severity.HIGH)

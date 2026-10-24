from __future__ import annotations

import os
import shutil
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ceg import register as register_mod
from ceg.settings import load_families, load_settings
from ceg.store import Store

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "companion-platform"
T0 = datetime(2026, 10, 5, 9, 0, tzinfo=UTC)


@pytest.fixture(scope="session")
def reg() -> register_mod.Register:
    return register_mod.load(EXAMPLE / "register.yaml")


@pytest.fixture(scope="session")
def families():
    return load_families()


@pytest.fixture(scope="session")
def settings():
    return load_settings()


@pytest.fixture(scope="session")
def _db() -> Iterator[Store]:
    dsn = os.environ.get("CEG_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("CEG_TEST_DATABASE_URL not set")
    store = Store(dsn)
    with store.conn() as c:
        c.execute("DROP SCHEMA public CASCADE")
        c.execute("CREATE SCHEMA public")
    store.migrate()
    yield store


@pytest.fixture
def store(_db: Store) -> Store:
    with _db.conn() as c:
        c.execute("TRUNCATE pages, alerts, issue_events, scans, issues RESTART IDENTITY CASCADE")
    return _db


def need_scanners() -> None:
    if not (shutil.which("semgrep") and shutil.which("bandit")):
        pytest.skip("semgrep and bandit are needed")

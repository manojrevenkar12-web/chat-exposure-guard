"""The deduplication benchmark runs end to end and our tracker makes no errors on it."""

import importlib.util
import sys

import pytest

from .conftest import ROOT, need_scanners

pytestmark = [pytest.mark.scanners, pytest.mark.slow]


def test_dedup_benchmark():
    need_scanners()
    spec = importlib.util.spec_from_file_location("dedup", ROOT / "bench" / "dedup.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["dedup"] = mod  # dataclasses look their module up
    spec.loader.exec_module(mod)
    res = mod.run()
    ours = res["summary"]["chat-exposure-guard"]
    assert all(ours[m] == 0 for m in mod.METRICS), ours
    assert ours["open at the end"] == ours["true open"]
    line = res["summary"]["tool + rule + path + line"]
    assert line["false new issues"] > 0 and line["false fixes"] > 0  # the baseline is measurably worse

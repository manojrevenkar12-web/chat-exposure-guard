# Stale source cache made moved findings look new and fixed ones look present

Date: 2026-10-23. Found by: `tests/test_matching.py::test_lines_moving_does_not_create_a_new_issue_but_does_for_the_line_baseline` (failed
while the matcher was being written). Impact: none in production; the bug never shipped.

## What happened

`SourceIndex` reads a file to find the enclosing function and the flagged line's text. Its caches
were keyed by path. When one process scanned the same path at two commits (the pull-request
review, the benchmark, and any long-running worker), the second scan read the first commit's
lines: the matcher compared the new finding's line number with old text, found a different
snippet, and treated a line move as a new issue plus a fix of the old one: exactly the duplicate
and false-fix pattern the project exists to prevent.

## Why it was not obvious

Every single-commit test passed. The failure needs two versions of one file in one process.

## Fix

The caches are keyed by `(path, mtime_ns, size)` (`source._version`). The matching tests now always
rewrite files between scans, and `bench/dedup.py` runs eleven commits through one process.

## What we keep from it

Anything that caches by name in a tool built to compare versions is suspicious. The benchmark is
now part of CI so that a regression of this kind fails a build, not a triage queue.

# 0001 An issue is a weakness at a place in the code, not a line a tool printed

Status: accepted, 2026-10-20

## Context

Scanners report `(tool, rule, path, line)`. Lines move with every edit above them, files get
renamed, functions move, and two tools (Semgrep and Bandit) report the same SQL injection under
different rule ids. Trackers that key on the tool's output (the default in most vulnerability
managers; DefectDojo's cross-tool deduplication is a paid feature) close the old issue and open a
new one on each of these changes. The security team then triages duplicates, and worse, a weakness
that is still there shows as "fixed" and loses its due date.

## Decision

* A **family** (`config/rule_families.yaml`) maps rules of different tools that describe the same
  weakness to one name with one CWE. Detections of one family at one place are one issue.
* For code, the place is the **enclosing symbol** (from the Python AST; a brace heuristic for
  TypeScript) plus the **normalised text of the flagged line**. Matching tries, in order: the same
  text in the same file; the same function within a 12-line window; the same function and text in
  a renamed or moved file; the same text in a renamed function; module-level code by position.
* Renames from `git diff -M` are applied before matching.
* Dependencies match on advisory alias overlap (CVE, GHSA, OSV ids); secrets on a salted hash of
  the value; configuration findings on family + resource.

## Consequences

* `bench/dedup.py` measures it against two baselines on one history: no false new issues, fixes or
  reopens for this tracker; 30 false new issues and 25 false fixes for `(tool, rule, path, line)`.
* Two identical weaknesses in one function more than 12 lines apart stay two issues
  (`tests/test_matching.py::test_two_weaknesses_of_one_family_far_apart_in_a_function_stay_two`); two identical lines next to each other
  in one function would merge. We accept that.
* A rule that is not in a family never merges across tools, which is the safe direction.

# Working in this repository

Fast feedback: `pytest -q -m "not db and not scanners"` (seconds); `pytest -q` adds PostgreSQL
(`CEG_TEST_DATABASE_URL`), the real scanners (`pip install -e ".[scanners]"`) and the benchmark.
`ceg aisec` and `python bench/dedup.py` are CI gates; `ruff check`, `ruff format --check`, `mypy`.

Invariants (each has a test):
- A secret's value is never stored or logged, only its salted hash (`tests/test_store.py`).
- A partial scan never marks an issue fixed; an issue is fixed only when every tool that reported
  it stops in a full scan of its scope (`tests/test_matching.py`).
- Severity is never lowered for secrets or configuration exposure (`config/settings.yaml: never_lower`).
- Thresholds, SLAs, allowlists, on-call and rule families live in `config/`, not in code.
- New Semgrep rules come with a test file next to them; `semgrep --test rules/` must pass.
- The prompt-injection harness judges outcomes from what the client loads and what tools ran,
  never from the defences' own verdicts, and the judge (`aisec/judge.py`) and the test client
  import nothing from `aisec/defences.py`.
- Held-out sets (`heldout/<set>`): never change rules, checks or defences to pass a set. Its first
  run (`reports/heldout/<set>/first_run.json`) is never rewritten. If you study a set's failures,
  write `regression` to `heldout/<set>/STATUS` and have someone who has not seen the code write a
  new set from `heldout/WRITING_CASES.md` or `heldout/WRITING_ATTACKS.md` only.
- Example and test data: attacker hosts end in `.example`; provider-format keys are generated at
  test time, never committed; chat content is ordinary and non-sexual, and nothing involves minors.

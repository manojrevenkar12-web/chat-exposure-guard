# Smaller defects found by the tests while building

| Date | Defect | Found by | Fix |
|---|---|---|---|
| 2026-10-21 | Semgrep rule files named `ceg.<id>.yaml` broke `semgrep --test` ("rule id mismatch") | rule tests | files named without the prefix; ids keep `ceg.` |
| 2026-10-21 | Owner-check exclusion `$ASSERT(..., $X, ...)` matched `db.delete(mem)` and hid an IDOR | rule test case | exclusion limited to named owner-check helpers and comparisons |
| 2026-10-22 | Logging rule flagged `len(message.content)` | rule test case | `pattern-not` for calls wrapping the content |
| 2026-10-22 | Terraform findings attributed to the wrong datastore (file-level mapping) | exposure test | `Datastore.resources` and `Register.datastore_for(path, resource)` |
| 2026-10-22 | Intentionally public character cards flagged as a public database | exposure test | `public_paths` in the register |
| 2026-10-22 | Leak guard missed a system prompt spaced out letter by letter | ablation | compare compacted and reversed text |
| 2026-10-24 | SARIF import took the first tag ("security") as the CWE, so CodeQL findings lost theirs | importer test | search all tags, drop leading zeros (`cwe-089` → `CWE-89`) |
| 2026-10-24 | Opening an issue logged a spurious "severity changed" event | store test | the opening event carries the first severity and its reason |

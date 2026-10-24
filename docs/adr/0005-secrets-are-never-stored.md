# 0005 A secret's value is never stored, only a salted hash

Status: accepted, 2026-10-20

Importers drop the matched value of a secret finding (gitleaks `Secret`/`Match`, GitHub secret
scanning payloads) and keep `sha256(salt || value)` with a per-installation salt
(`CEG_SECRET_SALT`). The hash deduplicates one key found in three files and across rescans; it
cannot be reversed, and a database dump cannot be used to look a key up without the salt. Snippets
of secret findings are stored as `[redacted]`. `tests/test_store.py` checks the database never holds
the value.

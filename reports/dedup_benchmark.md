# Deduplication benchmark

One history of the example platform, scanned after every commit by Semgrep (project rules), Bandit, the secret scanner and the exposure checks. Three trackers ingest the same results; git renames are given to all three. The truth column says what the commit really did.

| Tracker | False new issues | Missed new weaknesses | False fixes | Missed fixes | False reopens | Missed reopens | Open at the end (truth 29) |
|---|---|---|---|---|---|---|---|
| chat-exposure-guard | 0 | 0 | 0 | 0 | 0 | 0 | 29 |
| tool + rule + path + line | 30 | 0 | 25 | 0 | 1 | 0 | 35 |
| tool + rule + path + line text | 10 | 1 | 5 | 0 | 2 | 0 | 35 |

## Step by step

Each cell is opened / fixed / reopened.

| Commit | Truth | chat-exposure-guard | tool + rule + path + line | tool + rule + path + line text |
|---|---|---|---|---|
| initial commit | 29 / 0 / 0 | 29 / 0 / 0 | 35 / 0 / 0 | 35 / 0 / 0 |
| add request logging above the routes (lines shift) | 0 / 0 / 0 | 0 / 0 / 0 | 5 / 5 / 0 | 0 / 0 / 0 |
| reformat media.py (long calls split over lines) | 0 / 0 / 0 | 0 / 0 / 0 | 7 / 7 / 0 | 3 / 3 / 0 |
| rename media.py to processing.py | 0 / 0 / 0 | 0 / 0 / 0 | 7 / 7 / 0 | 0 / 0 / 0 |
| move GET /conversations/{id} to routes/conversations.py | 0 / 0 / 0 | 0 / 0 / 0 | 5 / 5 / 0 | 1 / 1 / 0 |
| rename search() to search_messages() | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 |
| add a trailing comment to the SQL line | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 |
| fix: verify TLS in processing.py | 0 / 1 / 0 | 0 / 1 / 0 | 0 / 2 / 0 | 0 / 2 / 0 |
| revert the TLS fix | 0 / 0 / 1 | 0 / 0 / 1 | 0 / 0 / 2 | 0 / 0 / 2 |
| new export endpoint without an owner check | 1 / 0 / 0 | 1 / 0 / 0 | 1 / 0 / 0 | 0 / 0 / 1 |
| fix: verify JWT signatures | 0 / 1 / 0 | 0 / 1 / 0 | 0 / 1 / 0 | 0 / 1 / 0 |

What the errors cost: a false new issue is a duplicate somebody triages and closes, with a fresh due date; a false fix makes a weakness that is still there disappear from the dashboard and its SLA clock; a missed new weakness is merged into an old issue and never reviewed; a missed reopen loses the history of a regression. Bandit and Semgrep reporting the same line are two issues for both baselines, so they also count one real fix twice.

Limits: one history of one example, eleven commits written by the author of the tracker. The point is the kind of change each approach survives, not a rate to quote.

Generated 2026-10-24T13:50:06+00:00 by `python bench/dedup.py`.

# chat-exposure-guard

**Application security for an AI companion platform: every path to users' private chats, found,
deduplicated, prioritised by what the service holds, and tracked until it is fixed.**

The large companion-app breaches of the past year were not clever attacks. They were configuration:

- an unauthenticated Kafka broker streaming 43 million messages and 600,000 images from two apps;
- a Firebase database with public rules exposing 300 million messages of 25 million users;
- provider keys and cloud service-account keys shipped inside the apps themselves.

On top of that, companion models read text other people wrote (character cards, stored memories,
web pages, community posts). A model that reads an injection can be made to put a user's
memories into an image URL, and the user's own chat client fetches it.

This repository is what one security engineer can run for such a platform, every week:

| Job | What runs | Where |
|---|---|---|
| **Code review before it ships** | 14 Semgrep rules written for chat platforms (IDOR on conversations, chat text in logs, user text in system prompts, model output as HTML, Markdown images from any host, provider keys in client code, unauthenticated brokers, week-long media URLs) plus Bandit, each rule with its own test file | [`rules/`](rules) |
| **Pull-request gate** | scans the base and the head of a PR, reports only what it introduces (a moved or reformatted function is not new), names the service and why the severity is what it is | [`review.py`](src/ceg/review.py), [reusable workflow](.github/workflows/security-review.yml) |
| **Exposure checks** | Kubernetes Services, Kafka `server.properties`, `redis.conf`, Firebase RTDB and Firestore rules, Terraform (S3, security groups, RDS, MSK, GCS) | [`exposure.py`](src/ceg/exposure.py) |
| **Secrets** | provider-aware scanner; a key in a shipped app is critical; values are never stored, only salted hashes | [`secrets.py`](src/ceg/secrets.py) |
| **One issue per weakness** | Semgrep, Bandit, SARIF (CodeQL), OSV-Scanner, gitleaks, ZAP, pentest reports and AI-provider advisories in one tracker. Identity survives line moves, reformatting, renamed files, moved and renamed functions, and two tools reporting one weakness | [`matching.py`](src/ceg/matching.py), [ADR 0001](docs/adr/0001-issue-identity.md) |
| **Risk register** | every service with its exposure, auth, data classes, datastores, AI providers and last pentest; severity is raised or lowered from it, with the reason recorded; residual risk per service | [`register.yaml`](examples/companion-platform/register.yaml), [ADR 0003](docs/adr/0003-severity-from-the-register.md) |
| **Prompt-injection defences, measured** | render policy, leak guard and tool broker, tested against a model that always obeys the injection, judged by what a permissive client loads and what tools ran | [`aisec/`](src/ceg/aisec), [ADR 0004](docs/adr/0004-assume-the-model-is-compromised.md) |
| **Weekend coverage** | signed webhooks (GitHub secret scanning, Dependabot, code scanning, generic), dedup window, on-call rotation, escalation primary → secondary → lead when nobody acknowledges | [`alerts.py`](src/ceg/alerts.py), [`oncall.yaml`](config/oncall.yaml) |
| **Access and devices** | HR roster against GitHub, Google Workspace, Slack, cloud IAM and the MDM: leavers with access, unknown accounts, admins without MFA, stale keys, unencrypted or silent laptops | [`access.py`](src/ceg/access.py) |
| **Company-wide update** | the weekly Markdown broadcast: new and serious, late, fixed, where the risk sits | [`report.py`](src/ceg/report.py) |

Everything has a CLI (`ceg --help`) and an HTTP API with role-based keys (reader, triager, admin).

## Results

All numbers below are produced by the code in this repository and re-run in CI.

### One issue per weakness, through a refactor

[`bench/dedup.py`](bench/dedup.py) commits the example platform to a fresh git repository and
changes it eleven times the way code really changes, scanning with the real tools after every
commit. Three trackers ingest the same results ([report](reports/dedup_benchmark.md)):

| Tracker | False new issues | Missed new weaknesses | False fixes | Missed fixes | False reopens | Missed reopens | Open at the end (truth 29) |
|---|---|---|---|---|---|---|---|
| **chat-exposure-guard** | **0** | **0** | **0** | **0** | **0** | **0** | **29** |
| tool + rule + path + line | 30 | 0 | 25 | 0 | 1 | 0 | 35 |
| tool + rule + path + line text | 10 | 1 | 5 | 0 | 2 | 0 | 35 |

The two baselines are the usual defaults: `(tool, rule, path, line)`, and the same with the line's
text instead of its number. A false fix is the expensive error: a weakness that is still in the code
disappears from the dashboard and its due date, and comes back later as a "new" issue.

### Rules and checks

- The example platform ([`examples/companion-platform`](examples/companion-platform)) has 29
  planted weaknesses listed in [`PLANTED.yaml`](examples/companion-platform/PLANTED.yaml): 17 in
  code and 12 in configuration. A scan finds **each one exactly once, with the expected severity,
  and nothing else** (`tests/test_rules.py`). These are the cases the rules were written against,
  so this shows the rules work, not how well they generalise.
- How well they generalise is what the held-out set measures:

RULES_HELDOUT

### Prompt injection

The model is simulated and always obeys the injection; what is measured is whether the platform
around it still stops the attacker. Development corpus, 38 attacks and 14 benign conversations
(`ceg aisec`):

| Defences | Attacks that succeeded | Benign conversations intact |
|---|---|---|
| no defences | 38/38 | 13/14 |
| render policy (escape HTML, images only from media hosts, inert links) | 14/38 | 14/14 |
| + leak guard (canary, overlap, decoded and reversed text) | 10/38 | 14/14 |
| + session binding (tools read only the session user's data) | 8/38 | 14/14 |
| + confirmation (sharing, email and phone changes) | 6/38 | 14/14 |
| + fetch allowlist | 5/38 | 14/14 |
| **all (+ taint check on outbound tool arguments)** | **0/38** | **14/14** |

Per goal (zero-click and one-click exfiltration, exfiltration through tools, cross-user access,
system-prompt leaks, unconfirmed actions) in [`reports/aisec_dev.md`](reports/aisec_dev.md).
These are the attacks the defences were built against.

Held-out sets, written by someone who had seen neither the defences nor the development corpus:

| Set | Status | First run, no defences | First run, every defence on | Benign intact (first run) |
|---|---|---|---|---|
| [`aisec-v1`](heldout/aisec-v1) | regression (studied) | 38/46 | 0/46 attacks succeeded | 20/22 |
| [`aisec-v2`](heldout/aisec-v2) | regression (studied) | 53/54 | **2/54** attacks succeeded | 24/25 |
| [`aisec-v3`](heldout/aisec-v3) | **held out** | 53/54 | **0/54** attacks succeeded | **22/22** |

First runs are kept unchanged in [`reports/heldout/`](reports/heldout); each set was written by a
different writer from [`WRITING_ATTACKS.md`](heldout/WRITING_ATTACKS.md) only, and run once before
anyone looked at its results. After the fixes below, v1 and v2 also run at 0 attacks and every benign
conversation intact, but that is no longer a measurement: their failures were studied.

## What the held-out sets taught

The first two prompt-injection sets found real problems, and the first code set showed how much
the rules had been fitted to their own examples:

1. **The judge could not see what the defences missed** (aisec-v1). It reused the leak guard and
   the tool broker's matcher to decide whether something leaked, so an encoding the guard did not
   know was invisible to the evaluation too. Eight v1 attacks "failed" even with no defences.
   The judge now has its own detector that imports nothing from the defences
   ([postmortem](docs/postmortems/2026-10-24-judge-shared-the-guards-detector.md)).
2. **Two attacks got through every defence** (aisec-v2): the system prompt's marker posted to the
   public character board (the taint check only knew the user's data), and the marker spelled out
   with spaces (the leak guard compared it verbatim). Both are now blocked.
3. **The render policy broke normal replies** (v1, v2): it rewrote a URL inside a code sample,
   escaped `&` in an image URL, and escaped an HTML snippet in a code block. Code is now passed
   through as written, and only `<` and `>` are escaped elsewhere.
4. **The rules found 40 of 58 weaknesses on their first unseen set, with 21 false alarms**
   (rules-v1, precision 0.66, 7 of 26 safe cases flagged). Misses were the shapes the development
   examples did not have: chat text logged through a variable rather than `message.content`,
   `session.verify = False`, JWT options kept in a module constant, a Redis client without a
   password, Firestore rules written through a helper function, ingress-nginx CORS annotations,
   react-markdown with a `components` object that has no `img` override. False alarms included
   `pickle.dumps`, Bandit's Hugging Face revision-pinning check counted as deserialization, and
   published character cards read as a public database. All are fixed with a rule test for each
   shape; rules-v1 is now a regression set, and rules-v2 was written by a new writer.

## Running it

```bash
pip install -e ".[dev,scanners]"           # Python 3.12; semgrep and bandit come with [scanners]
ceg scan examples/companion-platform --register examples/companion-platform/register.yaml --dry-run
ceg aisec                                  # the ablation table above
ceg access examples/access-review --today 2026-10-20
python bench/dedup.py                      # the deduplication benchmark

# with PostgreSQL
export CEG_DATABASE_URL=postgresql://localhost/ceg
ceg migrate
ceg scan examples/companion-platform --register examples/companion-platform/register.yaml --commit "$(git rev-parse HEAD)"
ceg import provider-advisories examples/provider-advisories/2026-10.yaml --register examples/companion-platform/register.yaml
ceg report --register examples/companion-platform/register.yaml
CEG_API_KEYS="$(openssl rand -hex 16):admin" ceg serve
```

Tests: `pytest -q` runs 102 tests (unit, PostgreSQL with `CEG_TEST_DATABASE_URL`, the real
scanners, the benchmark). Lint and types: `ruff check`, `ruff format --check`, `mypy`.

Deployment: [`Dockerfile`](Dockerfile) (non-root, read-only root filesystem) and
[`deploy/k8s/ceg.yaml`](deploy/k8s/ceg.yaml) (API with migrations as an init container, a
CronJob ticking escalation every minute, the weekly report). Operations:
[`docs/RUNBOOK.md`](docs/RUNBOOK.md). Bugs the tests found while building, with fixes:
[`docs/postmortems/`](docs/postmortems).

## Limits

- **The model in the prompt-injection harness is simulated.** That makes the evaluation
  reproducible and free, and answers "does the platform stop an attacker when the model is fooled";
  it does not measure how often a real model is fooled, nor jailbreaks or content-filter bypass.
  Moderation of generated content (what EverGuard-style systems do) is out of scope here, and so is
  any corpus of sexual content: all test conversations are ordinary.
- The example platform, the held-out cases and the access exports are synthetic. Planted
  weaknesses show the logic is right on known shapes; they are not a rate on a real codebase.
- Semgrep rules are pattern-based within one function; a missing owner check spread across
  helpers in several files is a pentest's job, which is why pentest reports import into the same
  tracker.
- Phishing simulations and training (a platform like Riot) are not part of this; the weekly
  update and the alert desk are where their results would be reported.

## Research this is built on

- Millions of private chats exposed by two AI companion apps (unauthenticated Kafka broker),
  [Malwarebytes, Oct 2025](https://www.malwarebytes.com/blog/news/2025/10/millions-of-very-private-chats-exposed-by-two-ai-companion-apps)
- AI chat app leak exposes 300 million messages tied to 25 million users (Firebase rules),
  [Malwarebytes, Feb 2026](https://www.malwarebytes.com/blog/news/2026/02/ai-chat-app-leak-exposes-300-million-messages),
  [404 Media](https://www.404media.co/massive-ai-chat-app-leaked-millions-of-users-private-conversations/)
- Cloud keys, exposed conversations and injectable chat in companion apps,
  [Oversecured](https://oversecured.com/blog/that-ai-you-confide-in-may-be-an-open-book-researchers-find-cloud-keys-exposed-conversations-and-injectable-chat-in-companion-apps)
- Markdown-image exfiltration in GitHub Copilot Chat and its fix,
  [Simon Willison](https://simonwillison.net/2024/Jun/16/github-copilot-chat-prompt-injection/);
  the wider pattern: [markdown-exfiltration](https://simonwillison.net/tags/markdown-exfiltration)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/) (LLM01 prompt
  injection, LLM02 sensitive information disclosure, LLM05 improper output handling, LLM06 excessive agency, LLM07 system prompt leakage)
- How a common vulnerability manager deduplicates (hash code or tool id, per tool):
  [DefectDojo deduplication algorithms](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/deduplication_algorithms)

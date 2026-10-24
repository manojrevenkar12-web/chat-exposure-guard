# Runbook

## When you are paged

Pages come from `ceg-alerts-tick` through Slack with the alert id. Acknowledge first, so the next
person is not woken: `POST /v1/alerts/{id}/ack {"who": "<you>"}` (triager key). Unacknowledged
critical pages go primary → secondary after 15 minutes → security lead after another 15.

### A provider key or other secret was committed (critical)

1. **Rotate before anything else.** Revoking the key is the fix; deleting the commit is not (forks,
   clones and CI caches keep it). For AI provider keys, set a spend limit on the new key.
2. Check the provider's usage for the old key since the commit time; unexpected usage is an
   incident (open one in the incident channel, keep the timeline).
3. If the key was in a shipped client (`exposure: client` in the register), the app version has it
   forever: the new key must live behind the platform's API, not in the app.
4. Close the alert; the issue closes itself when the next full scan no longer finds the value.

### A datastore or bucket is exposed (critical)

1. Close it first (security group, Service type, public access block), then investigate.
2. Pull access logs for the exposure window (S3 server access logs, VPC flow logs, Kafka/Redis
   client lists). Exposure of chat content or NSFW media with any outside access is a personal
   data breach: involve the DPO; the GDPR clock (72 hours to the authority) starts when we know.
3. Add the misconfiguration's shape to `src/ceg/exposure.py` if the checks did not catch it, with a
   test, and add the resource to the register.

### A researcher or pentester reports an IDOR on conversations

Treat as critical until shown otherwise. Reproduce with two test accounts, never with a real
user's data. Import the report (`ceg import pentest report.yaml --register ...`) so it gets an issue
id, a due date and a link to the code finding of the same family.

## Operations

| Task | How |
|---|---|
| Migrate the database | `ceg migrate` (the API's init container does it on deploy) |
| Import a scan from CI | `POST /v1/scans` with an admin key, or `ceg import <format> <file> --register ...` |
| Accept a risk | `ceg suppress CEG-12 --status risk_accepted --until 2026-12-01 --reason ... --actor ... --register register.yaml` (90 days at most) |
| Weekly update | `ceg report --register register.yaml` (the CronJob posts it Mondays 08:00 Berlin) |
| Access review | `ceg access <export-dir> --register register.yaml` (monthly, and on every leaver) |
| Rotate a webhook secret | set `CEG_WEBHOOK_SECRET_<SOURCE>` to the new value, then change it at the sender; requests with the old signature get 401 in between, and GitHub retries them |
| Rotate API keys | add the new `key:role` to `CEG_API_KEYS`, roll the Deployment, remove the old one |

## When the tracker itself misbehaves

* Duplicates after a refactor: run `python bench/dedup.py`; if it is clean, add the refactor shape
  to its `STEPS` and reproduce there before changing matching.
* An issue marked fixed that is still there: check `GET /v1/issues/{id}` events. A fix comes from a
  full scan by every reporting tool; a scan imported with the wrong `scope` or `full` flag is the
  usual cause.
* The database is down: CI scan imports fail (they retry on the next pipeline); pages already sent
  are not resent; the ticker resumes escalation from `next_escalation_at` when it is back.

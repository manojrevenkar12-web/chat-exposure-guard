<!-- first run 2026-10-24T13:24:10+00:00; never rewritten -->
## Held-out set rules-v1 (code and configuration)

80 cases, 58 planted weaknesses, 26 safe look-alikes.

- Found 40 of 58 (recall 0.69)
- 21 false alarms (precision 0.656)
- Safe cases with no finding: 19 of 26

| Category | Found | Missed | False alarms |
|---|---|---|---|
| bandit:B310 | 0 | 0 | 1 |
| bandit:B323 | 0 | 0 | 1 |
| bandit:B403 | 0 | 0 | 1 |
| bandit:B404 | 0 | 0 | 2 |
| bandit:B603 | 0 | 0 | 1 |
| bandit:B607 | 0 | 0 | 2 |
| broker-without-auth | 4 | 1 | 0 |
| bucket-public | 3 | 1 | 0 |
| chat-content-logged | 0 | 3 | 0 |
| chat-idor | 2 | 1 | 0 |
| command-injection | 2 | 1 | 2 |
| cors-credentials-wildcard | 1 | 2 | 0 |
| database-rules-public | 2 | 1 | 3 |
| datastore-exposed | 4 | 0 | 0 |
| hardcoded-credential | 3 | 2 | 0 |
| jwt-unverified | 1 | 2 | 0 |
| long-lived-media-url | 3 | 0 | 1 |
| markdown-image-exfiltration | 1 | 2 | 1 |
| model-output-as-html | 2 | 1 | 0 |
| sqli | 3 | 0 | 0 |
| tls-verification-off | 2 | 1 | 1 |
| unsafe-deserialization | 4 | 0 | 4 |
| untrusted-text-in-system-prompt | 3 | 0 | 1 |

Cases that came out wrong:

- c003: expected ['chat-content-logged'], found nothing (logger.info writes the incoming message text (body.text))
- c006: expected ['command-injection'], found ['bandit:B404', 'command-injection', 'command-injection'] (ffmpeg command f-string with the uploaded filename run with shell=True)
- c007: expected ['tls-verification-off'], found nothing (requests.Session with session.verify = False)
- c009: expected ['unsafe-deserialization'], found ['bandit:B403', 'unsafe-deserialization', 'unsafe-deserialization'] (chat session cache read back from Redis with pickle.loads)
- c018: expected ['hardcoded-credential'], found nothing (google_client_secret default is a literal high-entropy secret)
- c020: expected ['database-rules-public'], found ['database-rules-public', 'database-rules-public'] (RTDB users/$uid/conversations readable by any signed-in user (public character node is fine))
- c021: expected ['bucket-public', 'bucket-public'], found ['bucket-public'] (uploads bucket: public access block all false, and a bucket policy granting Principal * s3:GetObject)
- c022: expected nothing, found ['database-rules-public'] (RTDB: user subtree owner-only; published characters public read with creator-only writes)
- c024: expected ['chat-content-logged'], found nothing (log.debug writes each extracted memory text)
- c028: expected nothing, found ['bandit:B404', 'bandit:B603', 'bandit:B607', 'bandit:B607', 'command-injection'] (ffmpeg run with an argument list (no shell); the shell=True call is a constant string)
- c029: expected ['tls-verification-off'], found ['tls-verification-off', 'tls-verification-off'] (httpx.AsyncClient(verify=False) for link previews)
- c030: expected ['unsafe-deserialization', 'unsafe-deserialization'], found ['unsafe-deserialization', 'unsafe-deserialization', 'unsafe-deserialization'] (from_pretrained(..., trust_remote_code=True) and torch.load without weights_only)
- c031: expected ['jwt-unverified'], found nothing (websocket auth accepts algorithms ['HS256', 'none'])
- c034: expected ['broker-without-auth'], found nothing (redis.Redis to a cluster host with no password and no TLS)
- c037: expected ['cors-credentials-wildcard'], found nothing (custom middleware reflects any Origin with Access-Control-Allow-Credentials: true)
- c038: expected ['model-output-as-html'], found nothing (streamed reply deltas appended to bubble.innerHTML)
- c040: expected ['markdown-image-exfiltration'], found nothing (markdown-it + default DOMPurify: HTML is sanitised but <img> from any host survives)
- c043: expected ['database-rules-public'], found nothing (Firestore users/{uid}/memories allows read, write to any signed-in user)
- c046: expected ['chat-idor'], found nothing (class-based (cbv) router: DELETE /uploads/{id} filters only by id, deletes object and row)
- c048: expected ['chat-content-logged'], found nothing (print() of the model reply text behind a debug flag)
- c050: expected ['command-injection'], found nothing (asyncio.create_subprocess_shell with sox and a path taken from the job payload)
- c051: expected ['tls-verification-off'], found ['bandit:B310', 'bandit:B323', 'tls-verification-off'] (urllib urlopen with ssl._create_unverified_context())
- c052: expected nothing, found ['unsafe-deserialization', 'unsafe-deserialization'] (yaml.safe_load / SafeLoader, torch.load(weights_only=True), from_pretrained without remote code)
- c054: expected ['jwt-unverified'], found nothing (options dict with verify_signature False kept in a module constant and passed to jwt.decode)
- c056: expected nothing, found ['untrusted-text-in-system-prompt'] (system prompt chosen from a constant persona dict; user text only in the messages list)
- c063: expected nothing, found ['long-lived-media-url'] (presigned POST 5 min, presigned GET 15 min, GCS signed URL exactly 24 hours)
- c064: expected ['cors-credentials-wildcard'], found nothing (ingress-nginx annotations: cors-allow-origin '*' with cors-allow-credentials 'true')
- c067: expected ['markdown-image-exfiltration'], found nothing (react-markdown with custom code/a components but default img handling)
- c069: expected nothing, found ['markdown-image-exfiltration'] (img component renders only https images from the platform's own media hosts)
- c070: expected ['hardcoded-credential', 'hardcoded-credential'], found ['hardcoded-credential'] (bundled app-config.json holds a literal llm apiToken, and the Anthropic SDK is created in browser code)
- c078: expected nothing, found ['database-rules-public'] (Firestore: published characters world-readable (meant to be public); everything under users/{uid} owner-only)

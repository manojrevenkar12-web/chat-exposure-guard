<!-- first run 2026-10-24T14:04:08+00:00; never rewritten -->
## Held-out set rules-v2 (code and configuration)

90 cases, 81 planted weaknesses, 30 safe look-alikes.

- Found 55 of 81 (recall 0.679)
- 5 false alarms (precision 0.917)
- Safe cases with no finding: 29 of 30

| Category | Found | Missed | False alarms |
|---|---|---|---|
| broker-without-auth | 6 | 1 | 0 |
| bucket-public | 5 | 0 | 0 |
| chat-content-logged | 0 | 4 | 0 |
| chat-idor | 1 | 4 | 0 |
| command-injection | 4 | 0 | 0 |
| cors-credentials-wildcard | 1 | 4 | 0 |
| database-rules-public | 4 | 1 | 2 |
| datastore-exposed | 4 | 1 | 0 |
| hardcoded-credential | 4 | 1 | 1 |
| jwt-unverified | 4 | 0 | 0 |
| long-lived-media-url | 2 | 2 | 0 |
| markdown-image-exfiltration | 1 | 4 | 0 |
| model-output-as-html | 3 | 2 | 1 |
| sqli | 4 | 0 | 0 |
| tls-verification-off | 4 | 0 | 1 |
| unsafe-deserialization | 5 | 0 | 0 |
| untrusted-text-in-system-prompt | 3 | 2 | 0 |

Cases that came out wrong:

- d001: expected ['chat-content-logged', 'chat-idor'], found ['chat-idor'] (GET /conversations/{id} loads by id with db.get and never compares user_id; logs the last message text)
- d003: expected ['chat-idor'], found nothing (Flask DELETE /api/memories/<id> uses get_or_404 and deletes without comparing owner (GET in same file does check))
- d005: expected ['chat-idor'], found nothing (Django CharacterDetailView.patch loads Character by pk and saves edits without an owner check (get is scoped))
- d007: expected ['chat-idor'], found nothing (aiohttp GET /uploads/{id} fetches the row by id via asyncpg and streams it without comparing owner_id to request user)
- d008: expected ['chat-idor'], found nothing (MessageRoutes.edit uses repo.get(message_id) (no user filter) while remove uses get_for_user)
- d010: expected ['chat-content-logged', 'untrusted-text-in-system-prompt'], found ['untrusted-text-in-system-prompt'] (reply worker puts the user's profile bio into the second system block and prints the reply text)
- d011: expected ['broker-without-auth', 'broker-without-auth', 'chat-content-logged'], found ['broker-without-auth', 'broker-without-auth'] (kafka-python KafkaConsumer and KafkaProducer both connect with only bootstrap_servers (no SASL/SSL); flagged message text logged with warning())
- d012: expected ['chat-content-logged', 'untrusted-text-in-system-prompt'], found ['untrusted-text-in-system-prompt'] (stored memories joined into the OpenAI system message; structlog debug logs each memory's text)
- d016: expected ['untrusted-text-in-system-prompt'], found nothing (PromptBuilder.build_instructions formats profile bio and interests into Responses API instructions)
- d019: expected ['tls-verification-off', 'untrusted-text-in-system-prompt'], found ['tls-verification-off'] (link summariser fetches the page with ssl._create_unverified_context and puts page text into the system prompt)
- d042: expected ['cors-credentials-wildcard', 'jwt-unverified'], found ['jwt-unverified'] (flask_cors origins '*' with supports_credentials=True; before_request trusts jose get_unverified_claims)
- d043: expected ['jwt-unverified'], found ['jwt-unverified', 'tls-verification-off'] (Channels websocket consumer decodes the query-string JWT with legacy jwt.decode(token, verify=False))
- d048: expected ['broker-without-auth'], found nothing (confluent_kafka Producer config dict from settings has only bootstrap.servers/acks, no security.protocol)
- d053: expected ['long-lived-media-url'], found nothing (presign TTL comes from settings.media_url_ttl_seconds whose default is 48 hours)
- d054: expected ['long-lived-media-url'], found nothing (CloudFrontSigner URL for voice notes with date_less_than = now + 30 days)
- d056: expected ['cors-credentials-wildcard'], found nothing (aiohttp_cors.setup defaults keyed '*' with allow_credentials=True)
- d057: expected ['cors-credentials-wildcard', 'hardcoded-credential'], found ['hardcoded-credential', 'hardcoded-credential'] (django-cors-headers CORS_ALLOW_ALL_ORIGINS with CORS_ALLOW_CREDENTIALS; DATABASES PASSWORD is a literal secret)
- d058: expected ['cors-credentials-wildcard'], found nothing (CORSMiddleware allow_origin_regex from settings defaults to 'https?://.*' with allow_credentials=True)
- d062: expected ['model-output-as-html'], found nothing (Vue bubble renders a computed string (reply text with newlines turned into <br>) through v-html)
- d063: expected ['model-output-as-html'], found nothing (Svelte component renders the assistant message body with {@html})
- d065: expected nothing, found ['model-output-as-html'] (reply HTML sanitised by DOMPurify (img forbidden); plain text via JSX; a constant footer string uses dangerouslySetInnerHTML)
- d067: expected ['markdown-image-exfiltration'], found nothing (markdown-it output sanitised with DOMPurify (which keeps <img> from any https host) then set as innerHTML)
- d068: expected ['markdown-image-exfiltration'], found nothing (Vue computed marked.parse(reply) sanitised by DOMPurify keeps images from any host)
- d069: expected ['markdown-image-exfiltration'], found nothing (showdown output passed through sanitize-html configured to allow <img src> with http/https schemes)
- d070: expected ['markdown-image-exfiltration'], found nothing (react-markdown overrides img with a lazy-loading <img> that still accepts any src)
- d075: expected ['datastore-exposed', 'hardcoded-credential'], found ['datastore-exposed'] (Deployment sets DB_PASSWORD as a literal env value; redis Service is type NodePort)
- d077: expected ['datastore-exposed'], found nothing (Helm values expose Kafka through externalAccess Service type LoadBalancer with empty loadBalancerSourceRanges and no internal annotation)
- d082: expected ['database-rules-public'], found ['database-rules-public', 'database-rules-public'] (Realtime Database rules set .read and .write true at the root)
- d083: expected ['database-rules-public', 'database-rules-public'], found ['database-rules-public', 'database-rules-public', 'database-rules-public'] (conversations readable/writable by any signed-in user (auth != null); uploads/$uid readable by everyone; publicCharacters is fine)
- d085: expected ['database-rules-public'], found nothing (Firestore test-mode rule: everything readable and writable by anyone until a date)

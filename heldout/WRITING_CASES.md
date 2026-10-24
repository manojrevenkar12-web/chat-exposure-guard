# Writing a held-out set of code and configuration cases

You are writing test cases for a security scanner you have **not seen**. Do not open `src/`,
`rules/`, `config/`, `examples/`, `tests/`, `bench/` or any other held-out set. Everything you need
is in this file. The point of the set is to find out how the scanner does on code it was not
written against, so write cases the way real teams write code, including the variations a careless
rule would miss and the safe look-alikes a careless rule would flag.

## What the scanner is for

It protects a companion-chat platform: users talk to AI characters, the platform stores their
conversations, memories the model extracts from them, uploaded images, and account data. The
scanner looks at Python (FastAPI, SQLAlchemy, requests, boto3, kafka-python, redis-py, PyJWT,
the Anthropic/OpenAI SDKs), browser TypeScript/JavaScript (React), JSON app configs, and
infrastructure configuration (Kubernetes YAML, Kafka `server.properties`, `redis.conf`, Firebase
Realtime Database rules JSON, Firestore rules, Terraform for AWS and GCP).

## The categories

Each weakness a case contains is labelled with exactly one of these names.

| Category | What it means |
|---|---|
| `chat-idor` | An HTTP route loads a record that belongs to a user (conversation, message, memory, character, upload) by an id taken from the request and returns, changes or deletes it without ever comparing its owner with the signed-in user. |
| `chat-content-logged` | The text of a user's message, a model reply or a memory is written to a log (logging module, print, a logger's methods). Logging ids, lengths or counts is fine. |
| `sqli` | SQL text is assembled from values by string formatting, concatenation or f-strings and executed. Parameterised queries are fine. |
| `command-injection` | A shell command is built from a non-constant value and run through a shell. |
| `tls-verification-off` | An HTTP client call or session disables certificate verification. |
| `unsafe-deserialization` | Data is loaded with a format that can execute code: pickle, yaml.load without a safe loader, torch.load without weights_only=True, Hugging Face loading with trust_remote_code=True. |
| `jwt-unverified` | A JWT is decoded without verifying its signature, or with the "none" algorithm accepted. |
| `untrusted-text-in-system-prompt` | Text that a user (or another user) wrote, such as stored memories, a character description written by users, a profile bio, or a fetched web page, is put into the system prompt of a model call. Constant strings are fine. |
| `broker-without-auth` | A Kafka or Redis client in code connects without authentication or TLS; or the broker's own configuration accepts unauthenticated or plaintext clients on a non-loopback interface; or a managed broker (MSK) allows unauthenticated access. |
| `long-lived-media-url` | A signed URL for private media stays valid for more than a day. |
| `cors-credentials-wildcard` | CORS allows any origin together with credentials. |
| `model-output-as-html` | Model or chat output is inserted into the page as raw HTML (dangerouslySetInnerHTML, innerHTML, v-html and similar) without sanitising. |
| `markdown-image-exfiltration` | Chat or model output is rendered as Markdown with images allowed from any host, so a reply can make the browser load an attacker's URL. A renderer that restricts image sources or drops images is fine. |
| `hardcoded-credential` | A real-looking provider key or secret is written into source or config, or an AI provider SDK client is created in browser or mobile app code (which ships the key to users). Placeholders like `your-key-here` or `${OPENAI_API_KEY}` are fine. |
| `datastore-exposed` | A datastore port is published to the internet: Kubernetes Service of type LoadBalancer/NodePort for a database, cache or broker without an internal annotation or source ranges; a security group opening a datastore port (or all ports) to 0.0.0.0/0; a publicly accessible RDS instance. |
| `database-rules-public` | Firebase Realtime Database or Firestore rules let anyone, or any signed-in user, read or write data that belongs to individual users. Data that is meant to be public (for example published character cards) is fine. |
| `bucket-public` | A storage bucket is made public: S3 public access block turned off, a bucket policy or ACL granting everyone, a GCS binding to allUsers or allAuthenticatedUsers. |

## Layout

    heldout/<set>/cases/<case-id>/<any files and directories>
    heldout/<set>/answers.yaml

A case is a directory with one to three small files that look like part of a real service. Use
realistic paths (`services/chat/app/routes.py`, `infra/k8s/redis.yaml`, `web/src/Reply.tsx`).
`answers.yaml`:

```yaml
cases:
  - id: c001
    expect: [chat-idor]          # every weakness in the case, one entry per weakness
    note: "PATCH /memories/{id} updates without an owner check"
  - id: c002
    expect: []                   # a safe case: nothing may be reported
    note: "owner compared through a helper that raises 404"
```

If a case has the same category twice in different places, list it twice.

## What a good set looks like

* 60 to 80 cases. About a third safe look-alikes (`expect: []`): the code a sloppy rule would flag
  but which is correct.
* Every category appears at least three times as a weakness, written in different ways: different
  libraries and call styles, aliases and imports, values passed through variables or helper
  functions, multi-line calls, async and sync code, class-based routers.
* Do not try to defeat the scanner with tricks no developer would write (string obfuscation,
  eval). Write what real code looks like.
* Code does not have to run, but it should be plausible and syntactically valid in its language.

## Content rules

* Defensive testing only. Attacker-controlled hosts use the reserved `.example` domain.
* Never write a provider-format key (anything starting `sk-`, `sk-ant-`, `AIza`, `AKIA`, `ghp_`,
  `xoxb-` and the like) as a literal: GitHub push protection blocks them. For
  `hardcoded-credential` cases use a high-entropy generic secret assigned to a credential-like name
  (`client_secret`, `api_token`, `password`, `DB_PASSWORD`), for example
  `"Vf3qT9zLm2Rk8sWb1nYc6uHd"`, or an AI SDK client created in browser or mobile code (for example
  with `dangerouslyAllowBrowser: true`, or with the key read from a bundled config).
* Chat content in cases is ordinary and non-sexual; nothing involving minors.

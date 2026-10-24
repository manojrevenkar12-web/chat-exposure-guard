-- chat-exposure-guard schema. Applied in order by `ceg migrate`; each file runs once.

CREATE TABLE IF NOT EXISTS issues (
    id               text PRIMARY KEY,
    seq              bigint NOT NULL UNIQUE,
    kind             text NOT NULL,
    family           text NOT NULL,
    title            text NOT NULL,
    cwe              text NOT NULL DEFAULT '',
    service          text NOT NULL DEFAULT '',
    tool_severity    text NOT NULL,
    severity         text NOT NULL,
    severity_reason  text NOT NULL DEFAULT '',
    status           text NOT NULL CHECK (status IN ('open', 'fixed', 'risk_accepted', 'false_positive')),
    first_seen       timestamptz NOT NULL,
    last_seen        timestamptz NOT NULL,
    opened_at        timestamptz NOT NULL,
    due_at           timestamptz NOT NULL,
    fixed_at         timestamptz,
    reopen_count     integer NOT NULL DEFAULT 0,
    accepted_until   timestamptz,
    reporting        jsonb NOT NULL DEFAULT '{}',
    anchors          jsonb NOT NULL DEFAULT '[]',
    path             text NOT NULL DEFAULT '',
    symbol           text NOT NULL DEFAULT '',
    ecosystem        text NOT NULL DEFAULT '',
    package          text NOT NULL DEFAULT '',
    advisories       text[] NOT NULL DEFAULT '{}',
    secret_hash      text NOT NULL DEFAULT '',
    resource         text NOT NULL DEFAULT '',
    locations        text[] NOT NULL DEFAULT '{}',
    detections       integer NOT NULL DEFAULT 0,
    ticket_url       text NOT NULL DEFAULT '',
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS issues_status_severity ON issues (status, severity, due_at);
CREATE INDEX IF NOT EXISTS issues_service ON issues (service);

-- Append-only audit trail: every state change of every issue, with the scan that caused it.
CREATE TABLE IF NOT EXISTS issue_events (
    id        bigserial PRIMARY KEY,
    issue_id  text NOT NULL REFERENCES issues (id),
    at        timestamptz NOT NULL,
    kind      text NOT NULL,
    detail    text NOT NULL,
    scan_id   text NOT NULL DEFAULT '',
    actor     text NOT NULL DEFAULT 'system'
);
CREATE INDEX IF NOT EXISTS issue_events_issue ON issue_events (issue_id, at);

CREATE TABLE IF NOT EXISTS scans (
    id           text PRIMARY KEY,
    tool         text NOT NULL,
    scope        text NOT NULL,
    full_scan    boolean NOT NULL,
    commit_sha   text NOT NULL DEFAULT '',
    at           timestamptz NOT NULL,
    findings     integer NOT NULL,
    opened       integer NOT NULL DEFAULT 0,
    fixed        integer NOT NULL DEFAULT 0,
    reopened     integer NOT NULL DEFAULT 0,
    imported_at  timestamptz NOT NULL DEFAULT now()
);

-- Security alerts from GitHub, cloud providers and monitoring, and who was paged about them.
CREATE TABLE IF NOT EXISTS alerts (
    id                  bigserial PRIMARY KEY,
    source              text NOT NULL,
    dedup_key           text NOT NULL,
    severity            text NOT NULL,
    title               text NOT NULL,
    payload             jsonb NOT NULL,
    status              text NOT NULL CHECK (status IN ('open', 'acked', 'resolved')),
    occurrences         integer NOT NULL DEFAULT 1,
    received_at         timestamptz NOT NULL,
    last_received_at    timestamptz NOT NULL,
    acked_by            text,
    acked_at            timestamptz,
    level               integer NOT NULL DEFAULT 0,
    next_escalation_at  timestamptz,
    issue_id            text REFERENCES issues (id)
);
CREATE UNIQUE INDEX IF NOT EXISTS alerts_open_dedup ON alerts (dedup_key) WHERE status <> 'resolved';

CREATE TABLE IF NOT EXISTS pages (
    id        bigserial PRIMARY KEY,
    alert_id  bigint NOT NULL REFERENCES alerts (id),
    level     integer NOT NULL,
    target    text NOT NULL,
    channel   text NOT NULL,
    sent_at   timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_migrations (
    name        text PRIMARY KEY,
    applied_at  timestamptz NOT NULL DEFAULT now()
);

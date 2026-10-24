# 0003 Severity comes from the tool and from what the service holds

Status: accepted, 2026-10-21

The same missing TLS verification is a nuisance in an offline analytics job and a critical issue
in the service that relays chat content. The risk register (`register.yaml`, reviewed like code)
records each service's exposure (internet, partner, internal, offline, client), authentication,
the data classes it and its datastores hold, and its paths and resources.

* Raised one level when the service is internet-facing or a shipped client **and** holds one of
  chat content, NSFW media, payment, credentials or PII.
* Lowered one level when the service is internal or offline and holds none of those.
* **Never lowered** for secrets and configuration exposure: a leaked key or a public database is
  not less serious for living in a quiet corner.
* Every change carries its reason, shown in the issue, the API and the PR comment.

Due dates follow the effective severity (2/7/30/90 days). Residual risk per service is its
inherent risk (impact × likelihood) weighted by what is open there; an empty service keeps a fifth
of it, because no scan sees everything.

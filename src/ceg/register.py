"""The risk register, kept as code in ``register/services.yaml``.

Every service the company runs is listed with its owner, how it is exposed, which kinds of data it
holds and which paths in the repository belong to it. The register is the context that turns a
scanner's generic severity into a priority: a SQL injection in an internet-facing service that stores
chat logs is not the same problem as one in an internal batch job.
"""

from __future__ import annotations

import fnmatch
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator


class Exposure(StrEnum):
    INTERNET = "internet"  # reachable from the internet (directly or through a gateway)
    PARTNER = "partner"  # reachable by vendors or partners
    INTERNAL = "internal"  # only inside the private network
    OFFLINE = "offline"  # batch jobs, tooling


class DataClass(StrEnum):
    CHAT_CONTENT = "chat_content"  # users' conversations with companions
    NSFW_MEDIA = "nsfw_media"  # generated or uploaded intimate images and video
    PAYMENT = "payment"  # billing and purchase records
    PII = "pii"  # emails, device ids, IP addresses
    CREDENTIALS = "credentials"  # API keys, tokens, passwords of others
    MODEL_PROMPTS = "model_prompts"  # system prompts, character definitions
    TELEMETRY = "telemetry"  # product analytics without content
    PUBLIC = "public"


# How much each data class makes a breach hurt, 1 (nuisance) to 5 (company-ending).
IMPACT = {
    DataClass.CHAT_CONTENT: 5,
    DataClass.NSFW_MEDIA: 5,
    DataClass.CREDENTIALS: 5,
    DataClass.PAYMENT: 4,
    DataClass.PII: 4,
    DataClass.MODEL_PROMPTS: 2,
    DataClass.TELEMETRY: 2,
    DataClass.PUBLIC: 1,
}

LIKELIHOOD = {Exposure.INTERNET: 5, Exposure.PARTNER: 3, Exposure.INTERNAL: 2, Exposure.OFFLINE: 1}

SENSITIVE = {DataClass.CHAT_CONTENT, DataClass.NSFW_MEDIA, DataClass.PAYMENT, DataClass.CREDENTIALS, DataClass.PII}


class Datastore(BaseModel):
    name: str
    engine: str  # postgres, redis, kafka, firestore, s3, gcs, elasticsearch, ...
    data: list[DataClass]
    # Where the store's configuration lives in the repository (IaC, manifests, rules files)...
    config_paths: list[str] = Field(default_factory=list)
    # ...or, when one file configures several stores, which resources are this store's
    # (Terraform addresses such as aws_s3_bucket_policy.media).
    resources: list[str] = Field(default_factory=list)
    # Paths inside the store that are meant to be public (public character cards), as globs over
    # the paths in security rules, e.g. "/characters/*". Reviewed like any other risk acceptance.
    public_paths: list[str] = Field(default_factory=list)


class Service(BaseModel):
    name: str
    owner: str
    description: str = ""
    exposure: Exposure
    data: list[DataClass]
    paths: list[str] = Field(default_factory=list, description="glob patterns of the service's code")
    datastores: list[Datastore] = Field(default_factory=list)
    ai_providers: list[str] = Field(default_factory=list)
    auth: str = "session"  # session, api-key, mtls, none
    last_pentest: str = ""  # ISO date of the last external test, "" if never
    notes: str = ""

    @field_validator("name")
    @classmethod
    def _slug(cls, v: str) -> str:
        if not v or not all(c.isalnum() or c in "-_" for c in v):
            raise ValueError(f"service name {v!r} must be a slug")
        return v

    @property
    def impact(self) -> int:
        classes = set(self.data) | {d for ds in self.datastores for d in ds.data}
        return max((IMPACT[d] for d in classes), default=1)

    @property
    def likelihood(self) -> int:
        base = LIKELIHOOD[self.exposure]
        if self.auth == "none" and self.exposure in (Exposure.INTERNET, Exposure.PARTNER):
            base = 5
        return base

    @property
    def inherent_risk(self) -> int:
        """Impact × likelihood, 1–25, before any open finding is counted."""
        return self.impact * self.likelihood

    @property
    def holds_sensitive(self) -> bool:
        classes = set(self.data) | {d for ds in self.datastores for d in ds.data}
        return bool(classes & SENSITIVE)

    def owns(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, p) for p in self.paths)


class Register(BaseModel):
    services: list[Service]
    owners: list[str] = Field(default_factory=list)

    def get(self, name: str) -> Service | None:
        return next((s for s in self.services if s.name == name), None)

    def service_for_path(self, path: str) -> Service | None:
        """The service whose path patterns match; the most specific (longest) pattern wins."""
        best: tuple[int, Service] | None = None
        for s in self.services:
            for p in s.paths:
                if fnmatch.fnmatch(path, p) and (best is None or len(p) > best[0]):
                    best = (len(p), s)
        return best[1] if best else None

    def datastore_for(self, path: str, resource: str = "") -> tuple[Service, Datastore] | None:
        """The data store a configuration finding is about: by resource address first, then by file."""
        if resource:
            for s in self.services:
                for ds in s.datastores:
                    if any(resource == r or resource.endswith(":" + r) for r in ds.resources):
                        return s, ds
        for s in self.services:
            for ds in s.datastores:
                if any(fnmatch.fnmatch(path, p) for p in ds.config_paths):
                    return s, ds
        return None

    def validate_owners(self) -> list[str]:
        if not self.owners:
            return []
        return [f"{s.name}: owner {s.owner!r} is not in owners" for s in self.services if s.owner not in self.owners]


def load(path: str | Path) -> Register:
    data = yaml.safe_load(Path(path).read_text())
    reg = Register.model_validate(data)
    names = [s.name for s in reg.services]
    dupes = {n for n in names if names.count(n) > 1}
    if dupes:
        raise ValueError(f"duplicate services in register: {sorted(dupes)}")
    problems = reg.validate_owners()
    if problems:
        raise ValueError("; ".join(problems))
    return reg

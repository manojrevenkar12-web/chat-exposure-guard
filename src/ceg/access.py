"""Access review: who can still get in, and on which devices.

Reconciles the HR roster with exports from the systems that hold access (GitHub, Google Workspace,
Slack, the cloud's IAM) and the MDM's device list. Each problem becomes a finding, so it gets a due
date and an owner like any vulnerability: a leaver who can still push to GitHub is a critical issue,
not a line in a spreadsheet.

Inputs live in one directory: ``hr.csv``, and any of ``github.json``, ``google.json``,
``slack.json``, ``cloud_iam.json``, ``mdm.json``, ``aliases.yaml`` (login → email for accounts
whose email the export does not show, and ``service_accounts`` that have no person behind them).
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

from .models import Finding, Kind, Severity

SERVICE = "corporate-identity"


@dataclass(frozen=True)
class Person:
    email: str
    name: str
    status: str  # active, leaver, contractor
    end_date: date | None


def _d(s: str | None) -> date | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00")).date()


def _f(rule: str, title: str, sev: Severity, resource: str, desc: str, **ev: Any) -> Finding:
    return Finding(
        tool="ceg-access",
        rule=rule,
        kind=Kind.ACCESS,
        title=title,
        severity=sev,
        resource=resource,
        service=SERVICE,
        description=desc,
        evidence=ev,
        cwe="CWE-284",
    )


def review(
    directory: str | Path, today: date, stale_days: int = 90, inactive_admin_days: int = 60, device_checkin_days: int = 30
) -> list[Finding]:
    d = Path(directory)
    people: dict[str, Person] = {}
    with (d / "hr.csv").open() as fh:
        for r in csv.DictReader(fh):
            people[r["email"].lower()] = Person(
                r["email"].lower(), r.get("name", ""), r.get("status", "active").lower(), _d(r.get("end_date"))
            )
    aliases: dict[str, Any] = yaml.safe_load((d / "aliases.yaml").read_text()) if (d / "aliases.yaml").exists() else {}
    login_map = {k.lower(): v.lower() for k, v in (aliases.get("logins") or {}).items()}
    service_accounts = {s.lower() for s in aliases.get("service_accounts") or []}
    out: list[Finding] = []

    def gone(p: Person | None) -> bool:
        return p is not None and (p.status == "leaver" or (p.end_date is not None and p.end_date < today))

    def check_account(
        system: str, ident: str, email: str, active: bool, admin: bool, mfa: bool | None, last: date | None
    ) -> None:
        if not active:
            return
        key = f"{system}:{ident}"
        if email in service_accounts or ident.lower() in service_accounts:
            if admin and mfa is False:
                out.append(
                    _f(
                        "service-admin-without-mfa",
                        f"{system} service account {ident} is an admin without MFA",
                        Severity.HIGH,
                        key,
                        "Service accounts with admin rights need hardware-backed or federated auth.",
                    )
                )
            return
        person = people.get(email)
        if person is None:
            out.append(
                _f(
                    "unknown-account",
                    f"{system} account {ident} belongs to no one on the HR roster",
                    Severity.HIGH,
                    key,
                    "Find the owner, or remove the account. Add real service accounts to aliases.yaml.",
                )
            )
        elif gone(person):
            out.append(
                _f(
                    "leaver-active",
                    f"{person.name or email} left on {person.end_date or 'an earlier date'} "
                    f"but {system} account {ident} is active",
                    Severity.CRITICAL,
                    key,
                    "Deprovision now and review what the account did since the leaving date.",
                    left=str(person.end_date or ""),
                )
            )
        if admin and mfa is False:
            out.append(
                _f(
                    "admin-without-mfa",
                    f"{system} admin {ident} has no MFA",
                    Severity.HIGH,
                    key,
                    "Admin accounts are the shortest path to every user's chats; require phishing-resistant MFA.",
                )
            )
        elif mfa is False:
            out.append(
                _f(
                    "mfa-missing",
                    f"{system} account {ident} has no MFA",
                    Severity.MEDIUM,
                    key,
                    "Enforce MFA for the organisation.",
                )
            )
        if admin and last and (today - last).days > inactive_admin_days:
            out.append(
                _f(
                    "inactive-admin",
                    f"{system} admin {ident} unused for {(today - last).days} days",
                    Severity.MEDIUM,
                    key,
                    "Remove admin rights nobody uses.",
                )
            )

    for a in _json(d / "github.json"):
        email = (a.get("email") or login_map.get(a["login"].lower(), "")).lower()
        check_account("github", a["login"], email, True, a.get("role") == "admin", a.get("two_factor"), _d(a.get("last_active")))
        if a.get("outside_collaborator") and a.get("permission") in ("admin", "maintain"):
            out.append(
                _f(
                    "outside-collaborator-admin",
                    f"outside collaborator {a['login']} has {a['permission']} on {a.get('repo', 'a repository')}",
                    Severity.HIGH,
                    f"github:{a['login']}",
                    "Outside collaborators should have at most write access, for a limited time.",
                )
            )
    for a in _json(d / "google.json"):
        check_account(
            "google",
            a["email"],
            a["email"].lower(),
            not a.get("suspended", False),
            bool(a.get("is_admin")),
            a.get("mfa_enrolled"),
            _d(a.get("last_login")),
        )
    for a in _json(d / "slack.json"):
        check_account(
            "slack", a["email"], a["email"].lower(), not a.get("deleted", False), bool(a.get("is_admin")), a.get("has_2fa"), None
        )
    for a in _json(d / "cloud_iam.json"):
        email = (a.get("email") or login_map.get(a["user"].lower(), "")).lower()
        admin = any("admin" in p.lower() for p in a.get("policies", []))
        check_account("cloud", a["user"], email, True, admin, a.get("mfa"), _d(a.get("last_login")))
        for k in a.get("access_keys", []):
            created, used = _d(k.get("created")), _d(k.get("last_used"))
            age = (today - created).days if created else 0
            idle = (today - used).days if used else age
            if k.get("active", True) and (age > stale_days or idle > stale_days):
                out.append(
                    _f(
                        "stale-access-key",
                        f"cloud access key {k['id'][-4:]} of {a['user']} is {age} days old, idle {idle} days",
                        Severity.HIGH if admin else Severity.MEDIUM,
                        f"cloud:{a['user']}:{k['id'][-4:]}",
                        "Rotate or delete long-lived keys; prefer short-lived credentials from SSO.",
                    )
                )
    for dev in _json(d / "mdm.json"):
        owner = dev.get("assigned_email", "").lower()
        key = f"device:{dev['serial']}"
        checkin = _d(dev.get("last_checkin"))
        left = people[owner].end_date if owner in people else None
        if gone(people.get(owner)) and checkin and (left is None or checkin > left):
            out.append(
                _f(
                    "leaver-device-active",
                    f"device {dev['serial']} of a leaver ({owner}) still checks in",
                    Severity.HIGH,
                    key,
                    "Lock and wipe the device remotely; arrange its return.",
                )
            )
        if dev.get("encrypted") is False:
            out.append(
                _f(
                    "device-unencrypted",
                    f"device {dev['serial']} ({owner}) has disk encryption off",
                    Severity.HIGH,
                    key,
                    "A lost laptop with source code and production access must be encrypted.",
                )
            )
        if dev.get("os_up_to_date") is False:
            out.append(
                _f(
                    "device-os-outdated",
                    f"device {dev['serial']} ({owner}) misses OS security updates",
                    Severity.MEDIUM,
                    key,
                    "Enforce an OS update deadline in the MDM.",
                )
            )
        if checkin and (today - checkin).days > device_checkin_days and not gone(people.get(owner)):
            out.append(
                _f(
                    "device-silent",
                    f"device {dev['serial']} ({owner}) has not checked in for {(today - checkin).days} days",
                    Severity.LOW,
                    key,
                    "Confirm with the owner that the device is still in their hands.",
                )
            )
    return out


def _json(p: Path) -> list[dict[str, Any]]:
    if not p.exists():
        return []
    data = json.loads(p.read_text())
    return data if isinstance(data, list) else data.get("items", [])

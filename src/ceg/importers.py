"""Reading scanner output into findings.

Supported: Semgrep JSON, any SARIF 2.1 (CodeQL, Semgrep --sarif), Bandit JSON, OSV-Scanner JSON,
gitleaks JSON, ZAP's JSON report, and pentest reports in a small YAML or CSV format (most firms
deliver a PDF; someone types the findings into this format once, and retests are tracked from there).

Secret values are hashed with a salt on import and dropped; they are never stored.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from .models import Finding, Kind, Location, Severity

Importer = Callable[[Any], list[Finding]]

_DEV_SALT = "ceg-dev-salt-do-not-use-in-production"


def secret_hash(value: str) -> str:
    salt = os.environ.get("CEG_SECRET_SALT", _DEV_SALT)
    return hashlib.sha256((salt + "\x00" + value).encode()).hexdigest()


def first_sentence(text: str, limit: int = 160) -> str:
    t = " ".join(text.split())
    m = re.search(r"(?<=[.!?])\s", t)
    t = t[: m.start()] if m else t
    return t if len(t) <= limit else t[: limit - 1].rstrip() + "…"


def _sev(name: str, default: Severity = Severity.MEDIUM) -> Severity:
    n = (name or "").strip().lower()
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "error": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "moderate": Severity.MEDIUM,
        "warning": Severity.MEDIUM,
        "low": Severity.LOW,
        "note": Severity.LOW,
        "info": Severity.INFO,
        "informational": Severity.INFO,
        "none": Severity.INFO,
    }.get(n, default)


def _rel(path: str, root: str = "") -> str:
    p = path.replace("\\", "/")
    if root and p.startswith(root.rstrip("/") + "/"):
        p = p[len(root.rstrip("/")) + 1 :]
    return p.removeprefix("./")


def _ceg_rule(check_id: str) -> str:
    """Semgrep prefixes local rule ids with their directory (rules.python.ceg.x); keep the id."""
    i = check_id.find("ceg.")
    return check_id[i:] if i >= 0 else check_id


def _cwe(raw: Any) -> str:
    """First CWE id in a string or a list of tags, without leading zeros (CodeQL writes cwe-089)."""
    if isinstance(raw, list):
        raw = " ".join(str(x) for x in raw)
    m = re.search(r"CWE[-_/ ]?0*(\d+)", str(raw), re.I)
    return f"CWE-{m.group(1)}" if m else ""


def semgrep_json(doc: dict[str, Any], root: str = "") -> list[Finding]:
    out = []
    seen: set[tuple[str, str, int]] = set()
    for r in doc.get("results", []):
        key = (r["check_id"], r["path"], r["start"]["line"])
        if key in seen:  # one rule matching one line through several bindings is one finding
            continue
        seen.add(key)
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        sev = meta.get("ceg-severity") or extra.get("severity", "WARNING")
        out.append(
            Finding(
                tool="semgrep",
                rule=_ceg_rule(r["check_id"]),
                kind=Kind.CODE,
                title=first_sentence(extra.get("message", "")),
                severity=_sev(sev),
                cwe=_cwe(meta.get("cwe", "")),
                location=Location(_rel(r["path"], root), r["start"]["line"], r["end"]["line"], snippet=extra.get("lines", "")),
                evidence={"message": extra.get("message", "")},
            )
        )
    return out


def sarif(doc: dict[str, Any], root: str = "") -> list[Finding]:
    out = []
    for run in doc.get("runs", []):
        tool = run.get("tool", {}).get("driver", {})
        tool_name = (tool.get("name") or "sarif").lower().split()[0]
        rules = {r.get("id"): r for r in tool.get("rules", [])}
        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            rule = rules.get(rid, {})
            props = rule.get("properties", {})
            sev = props.get("security-severity")
            severity = (
                _cvss_band(float(sev))
                if sev
                else _sev(res.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning"))
            )
            locs = res.get("locations") or [{}]
            phys = locs[0].get("physicalLocation", {})
            region = phys.get("region", {})
            path = _rel(phys.get("artifactLocation", {}).get("uri", ""), root)
            out.append(
                Finding(
                    tool=tool_name,
                    rule=_ceg_rule(rid) if tool_name == "semgrep" else rid,
                    kind=Kind.CODE,
                    title=(res.get("message", {}).get("text") or rule.get("shortDescription", {}).get("text", rid))[:200],
                    severity=severity,
                    cwe=_cwe(props.get("tags", [])) or _cwe(props.get("cwe", "")),
                    location=Location(
                        path,
                        region.get("startLine", 0),
                        region.get("endLine", region.get("startLine", 0)),
                        snippet=region.get("snippet", {}).get("text", ""),
                    ),
                )
            )
    return out


def _cvss_band(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def bandit_json(doc: dict[str, Any], root: str = "") -> list[Finding]:
    out = []
    for r in doc.get("results", []):
        conf = r.get("issue_confidence", "MEDIUM").upper()
        sev = _sev(r.get("issue_severity", "MEDIUM"))
        if conf == "LOW" and sev.rank > Severity.LOW.rank:  # Bandit's low-confidence results are noisy
            sev = Severity.from_rank(sev.rank - 1)
        cwe = r.get("issue_cwe", {}) or {}
        rule = r["test_id"]
        if rule in ("B602", "B605") and r.get("issue_severity", "").upper() == "LOW":
            # Bandit rates shell=True with a constant command LOW: no input reaches the shell, so it is
            # not command injection and stays out of that family (held-out set rules-v1, c028)
            rule += "-constant"
        out.append(
            Finding(
                tool="bandit",
                rule=rule,
                kind=Kind.CODE,
                title=r.get("issue_text", "")[:200],
                severity=sev,
                cwe=f"CWE-{cwe['id']}" if cwe.get("id") else "",
                location=Location(
                    _rel(r["filename"], root),
                    r["line_number"],
                    max(r.get("line_range") or [r["line_number"]]),
                    snippet=r.get("code", ""),
                ),
                evidence={"confidence": conf},
            )
        )
    return out


def osv_scanner_json(doc: dict[str, Any], root: str = "") -> list[Finding]:
    out = []
    for res in doc.get("results", []):
        manifest = _rel(res.get("source", {}).get("path", ""), root)
        for pkg in res.get("packages", []):
            p = pkg["package"]
            groups = pkg.get("groups") or [{"ids": [v["id"]], "max_severity": ""} for v in pkg.get("vulnerabilities", [])]
            vulns = {v["id"]: v for v in pkg.get("vulnerabilities", [])}
            for g in groups:
                ids = set(g.get("ids", []))
                for vid in list(ids):
                    ids |= set(vulns.get(vid, {}).get("aliases", []))
                v: dict[str, Any] = next((vulns[i] for i in g.get("ids", []) if i in vulns), {})
                score = g.get("max_severity") or ""
                sev = (
                    _cvss_band(float(score))
                    if _is_float(score)
                    else _sev(v.get("database_specific", {}).get("severity", "MEDIUM"))
                )
                fixed = _fixed_version(v, p.get("name", ""))
                out.append(
                    Finding(
                        tool="osv-scanner",
                        rule=sorted(ids)[0],
                        kind=Kind.DEPENDENCY,
                        title=f"{p['name']} {p.get('version', '')}: {v.get('summary', sorted(ids)[0])}"[:200],
                        severity=sev,
                        location=Location(manifest),
                        ecosystem=p.get("ecosystem", ""),
                        package=p["name"],
                        version=p.get("version", ""),
                        advisory_ids=tuple(sorted(ids)),
                        fixed_version=fixed,
                        resource=manifest,
                    )
                )
    return out


def _is_float(s: Any) -> bool:
    try:
        float(s)
        return True
    except (TypeError, ValueError):
        return False


def _fixed_version(v: dict[str, Any], name: str) -> str:
    for aff in v.get("affected", []):
        if aff.get("package", {}).get("name", "").lower() != name.lower():
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    return str(ev["fixed"])
    return ""


# Rough sensitivity of credential types gitleaks reports, by rule id.
_SECRET_SEVERITY = {
    "gcp-service-account": Severity.CRITICAL,
    "aws-access-token": Severity.CRITICAL,
    "private-key": Severity.CRITICAL,
    "openai-api-key": Severity.HIGH,
    "anthropic-api-key": Severity.HIGH,
    "stripe-access-token": Severity.CRITICAL,
    "generic-api-key": Severity.MEDIUM,
    "jwt": Severity.MEDIUM,
}


def gitleaks_json(doc: list[dict[str, Any]], root: str = "") -> list[Finding]:
    out = []
    for r in doc:
        secret = r.get("Secret") or r.get("Match") or ""
        rule = r.get("RuleID", "generic-api-key")
        out.append(
            Finding(
                tool="gitleaks",
                rule=rule,
                kind=Kind.SECRET,
                title=f"{r.get('Description') or rule} in {r.get('File', '')}"[:200],
                severity=_SECRET_SEVERITY.get(rule, Severity.HIGH),
                location=Location(_rel(r.get("File", ""), root), int(r.get("StartLine", 0)), int(r.get("EndLine", 0))),
                secret_hash=secret_hash(secret),
                cwe="CWE-798",
                evidence={"commit": r.get("Commit", ""), "author": r.get("Author", "")},
            )
        )
    return out


_ZAP_RISK = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}
_ID_SEGMENT = re.compile(r"/(\d+|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{24,})(?=/|$)", re.I)


def endpoint(method: str, uri: str) -> str:
    """GET https://api.x/conversations/123?a=1 -> GET /conversations/{id}"""
    path = re.sub(r"^[a-z]+://[^/]+", "", uri, flags=re.I).split("?")[0] or "/"
    return f"{method.upper()} {_ID_SEGMENT.sub('/{id}', path)}"


def zap_json(doc: dict[str, Any], root: str = "", service: str = "") -> list[Finding]:
    out = []
    for site in doc.get("site", []):
        for a in site.get("alerts", []):
            sev = _ZAP_RISK.get(str(a.get("riskcode", "1")), Severity.LOW)
            seen: set[str] = set()
            for inst in a.get("instances", []) or [{}]:
                res = endpoint(inst.get("method", "GET"), inst.get("uri", site.get("@name", "")))
                if res in seen:
                    continue
                seen.add(res)
                out.append(
                    Finding(
                        tool="zap",
                        rule=str(a.get("pluginid", "")),
                        kind=Kind.DYNAMIC,
                        title=a.get("alert", a.get("name", ""))[:200],
                        severity=sev,
                        cwe=f"CWE-{a['cweid']}" if str(a.get("cweid", "")) not in ("", "-1", "0") else "",
                        resource=res,
                        service=service,
                        evidence={"param": inst.get("param", ""), "site": site.get("@name", "")},
                    )
                )
    return out


def pentest(doc: Any, root: str = "") -> list[Finding]:
    """YAML: {vendor, date, findings: [{id, title, severity, cwe, service, resource, description}]}
    or CSV with the same columns."""
    rows: list[dict[str, Any]]
    meta: dict[str, Any] = {}
    if isinstance(doc, str):
        rows = list(csv.DictReader(io.StringIO(doc)))
    else:
        meta = {k: v for k, v in doc.items() if k != "findings"}
        rows = doc.get("findings", [])
    out = []
    for r in rows:
        if not r.get("id") or not r.get("title"):
            raise ValueError(f"pentest finding needs id and title: {r}")
        out.append(
            Finding(
                tool="pentest",
                rule=str(r["id"]),
                kind=Kind.PENTEST,
                title=str(r["title"])[:200],
                severity=_sev(str(r.get("severity", "medium"))),
                cwe=_cwe(r.get("cwe", "")),
                resource=str(r.get("resource", r["id"])),
                service=str(r.get("service", "")),
                description=str(r.get("description", "")),
                evidence={"vendor": meta.get("vendor", ""), "date": str(meta.get("date", ""))},
            )
        )
    return out


def provider_advisories(doc: dict[str, Any], root: str = "", register: Any = None) -> list[Finding]:
    """Security advisories and incidents published by the AI providers the platform relies on.

    YAML: ``{advisories: [{id, provider, date, title, severity, url, action}]}``, kept by whoever
    watches the providers' status and security pages. Each advisory becomes one issue per service
    that uses the provider (``ai_providers`` in the register), so the owner of each service gets it
    with a due date, and a provider incident is followed up like any other finding.
    """
    out = []
    for a in doc.get("advisories", []):
        for k in ("id", "provider", "title"):
            if not a.get(k):
                raise ValueError(f"provider advisory needs {k}: {a}")
        provider = str(a["provider"]).lower()
        services = [s.name for s in register.services if provider in [p.lower() for p in s.ai_providers]] if register else []
        for svc in services or [""]:
            out.append(
                Finding(
                    tool="provider-advisory",
                    rule=str(a["id"]),
                    kind=Kind.AI,
                    title=f"{provider}: {a['title']}",
                    severity=_sev(str(a.get("severity", "medium"))),
                    resource=f"{provider}:{a['id']}@{svc or 'unmapped'}",
                    service=svc,
                    description=str(a.get("action", "")),
                    evidence={"provider": provider, "url": a.get("url", ""), "date": str(a.get("date", ""))},
                )
            )
    return out


FORMATS: dict[str, Callable[..., list[Finding]]] = {
    "provider-advisories": provider_advisories,
    "semgrep": semgrep_json,
    "sarif": sarif,
    "bandit": bandit_json,
    "osv-scanner": osv_scanner_json,
    "gitleaks": gitleaks_json,
    "zap": zap_json,
    "pentest": pentest,
}


def load(fmt: str, path: str | Path, root: str = "", **kw: Any) -> list[Finding]:
    if fmt not in FORMATS:
        raise ValueError(f"unknown format {fmt!r}; one of {sorted(FORMATS)}")
    text = Path(path).read_text()
    doc: Any
    if fmt == "pentest" and str(path).endswith(".csv"):
        doc = text
    elif fmt in ("pentest", "provider-advisories"):
        doc = yaml.safe_load(text)
    else:
        doc = json.loads(text) if text.strip() else ([] if fmt == "gitleaks" else {})
    return FORMATS[fmt](doc, root, **kw)
